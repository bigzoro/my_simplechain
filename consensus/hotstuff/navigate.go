package hotstuff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	bls "github.com/simplechain-org/go-simplechain/consensus/hotstuff/bls12-381"
	hots "github.com/simplechain-org/go-simplechain/consensus/hotstuff/common"
)

// An event of a node joined to removed from consensus replicas.
type event struct {
	kind   uint8
	expire uint64
	id     hots.ID
	pubkey *bls.PublicKey

	sig *bls.AggregateSignature

	hash []byte
}

type events []*event

func (set events) Len() int { return len(set) }

func (set events) Swap(i, j int) { set[i], set[j] = set[j], set[i] }

func (set events) Less(i, j int) bool {
	return set[i].expire < set[j].expire
}

func (ev *event) digest() []byte {
	if len(ev.hash) > 0 {
		return ev.hash
	}
	blknum := make([]byte, 8)
	binary.LittleEndian.PutUint64(blknum, ev.expire)
	texts := [][]byte{{ev.kind}, blknum, ev.id.Bytes()}
	if ev.kind == replicaJoined {
		texts = append(texts, ev.pubkey.ToBytes())
	}
	ev.hash = legacyCypherDigest(texts...).Bytes()
	return ev.hash
}

func (ev *event) verify(snap *snapshot, number uint64) error {
	if ev.expire <= number {
		// Discard the event if the timeout block height of the event has exceeded the
		// current mined block height.
		return fmt.Errorf("expired event for %d/%d", ev.expire, number)
	}

	return ev.sig.Verify(snap, ev.digest())
}

func (ev *event) apply(snap *snapshot) *snapshot {
	clone := snap.clone()
	switch ev.kind {
	case replicaJoined:
		clone.set(ev.id, ev.pubkey)
	case replicaRemoved:
		clone.remove(ev.id)
	}
	return clone
}

// navigation promotes the replica events to be applied to latest snapshot.
type navigation struct {
	mux    sync.RWMutex
	events map[hots.ID]*event
}

func newNavigation() *navigation {
	return &navigation{
		events: make(map[hots.ID]*event),
	}
}

func (nav *navigation) add(ev *event) error {
	nav.mux.Lock()
	defer nav.mux.Unlock()

	event, ok := nav.events[ev.id]

	if !ok || (event.kind == ev.kind && ev.expire > event.expire) {
		nav.events[ev.id] = ev
	}

	if ok && event.kind != ev.kind {
		delete(nav.events, ev.id)
		log.Debug("negating replica event", "kind", ev.kind, "id", ev.id)
	}

	return nil
}

func (nav *navigation) commit(snap *snapshot) *event {
	nav.mux.Lock()
	defer nav.mux.Unlock()

	var diffs events
	for id, event := range nav.events {
		pk, ok := snap.Pubkeys[id]
		switch event.kind {
		case replicaJoined:

			if !ok || !bytes.Equal(pk.ToBytes(), event.pubkey.ToBytes()) {
				diffs = append(diffs, event)
			} else {
				delete(nav.events, id)
				log.Debug("confirmed replica event", "kind", event.kind, "id", event.id)
			}

		case replicaRemoved:

			if ok {
				diffs = append(diffs, event)
			} else {
				delete(nav.events, id)
				log.Debug("confirmed replica event", "kind", event.kind, "id", event.id)
			}

		}
	}

	if len(diffs) > 0 {
		sort.Sort(diffs)
		return diffs[0]
	}
	return nil
}
