package hotstuff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bigzoro/my_simplechain/common"
	bls "github.com/bigzoro/my_simplechain/consensus/hotstuff/bls12-381"
	"github.com/bigzoro/my_simplechain/core/types"
	"golang.org/x/crypto/sha3"
)

const (
	// header.extra
	// field|| snapshot hash || signature length || aggregate signature || HotStuff replica event
	// bytes||       32      ||        2         ||         >96         ||  >(61+96)  or >(13+96)

	snapshotLen = 32 // The fixed length of replicas snapshot

	signLen = 2

	minAggsigLen = 96 // The minimum length of the serialized bytes of an aggregate signature.

	eventKind = 1

	expiredBlock = 8

	eventId = 4

	eventPublicKey = 48

	// Known replica event type.
	replicaJoined uint8 = 0xf1 + iota
	replicaRemoved
)

var (
	// HotStuff replica event
	// field|| event kind || expired block number || hotstuff id || public key || aggregate signature
	// bytes||      1     ||          8           ||      4      ||    0/48    ||         >96
	removedEventTopicLen = eventKind + expiredBlock + eventId

	joinedEventTopicLen = removedEventTopicLen + removedEventTopicLen

	// errInvalidExtra is returned if the extra format of a header does not comply
	// with the HotStuff type specification
	errInvalidExtra = errors.New("invalid extra field")
)

// In this HotStuff scheme, the quorum certificate is embedded in the block, and
// extract recovers the aggregate signature from block.extra.
func extract(header *types.Header) (common.Hash, *bls.AggregateSignature, *event, error) {
	if len(header.Extra) <= snapshotLen+signLen {
		return common.Hash{}, nil, nil, errInvalidExtra
	}

	siglen := binary.LittleEndian.Uint16(header.Extra[snapshotLen : snapshotLen+signLen])
	raw := header.Extra[snapshotLen+signLen:]
	if len(raw) < int(siglen) {
		return common.Hash{}, nil, nil, errInvalidExtra
	}
	sig := new(bls.AggregateSignature)
	if err := sig.FromBytes(raw[:siglen]); err != nil {
		return common.Hash{}, nil, nil, err
	}

	ev, err := extractReplicaEvent(header, true)

	return common.BytesToHash(header.Extra[:snapshotLen]), sig, ev, err
}

func extractSnapshot(header *types.Header, omit bool) (common.Hash, error) {
	if !omit && len(header.Extra) <= snapshotLen {
		return common.Hash{}, errInvalidExtra
	}
	return common.BytesToHash(header.Extra[:snapshotLen]), nil
}

func extractReplicaEvent(header *types.Header, omit bool) (*event, error) {
	extra := header.Extra
	if !omit && len(header.Extra) <= snapshotLen+signLen {
		return nil, errInvalidExtra
	}
	siglen := binary.LittleEndian.Uint16(header.Extra[snapshotLen : snapshotLen+signLen])
	extra = extra[snapshotLen+signLen+siglen:]

	if len(extra) == 0 {
		return nil, nil
	}
	ev := new(event)

	ev.kind = extra[:eventKind][0]
	switch ev.kind {
	case replicaJoined:
		if len(extra) < joinedEventTopicLen+minAggsigLen {
			return nil, fmt.Errorf("joined type event:%w", errInvalidExtra)
		}

	case replicaRemoved:
		if len(extra) < removedEventTopicLen+minAggsigLen {
			return nil, fmt.Errorf("removed type event:%w", errInvalidExtra)
		}

	default:
		return nil, fmt.Errorf("unknown event type:%x", ev.kind)
	}

	extra = extra[eventKind:]
	ev.expire = binary.LittleEndian.Uint64(extra[:expiredBlock])

	extra = extra[expiredBlock:]
	ev.id.FromBytes(extra[:eventId])

	extra = extra[eventId:]
	if ev.kind == replicaJoined {
		ev.pubkey = new(bls.PublicKey)
		if err := ev.pubkey.FromBytes(extra[:eventPublicKey]); err != nil {
			return nil, fmt.Errorf("extrat replica event public key:%w", err)
		}
		extra = extra[eventPublicKey:]
	}

	ev.sig = new(bls.AggregateSignature)
	if err := ev.sig.FromBytes(extra); err != nil {
		return nil, fmt.Errorf("extrat replica event aggregate signature:%w", err)
	}

	return ev, nil
}

// // seal serializes the content of an aggregate signature and embeds it into block.extra.
func seal(snapshot common.Hash, sig *bls.AggregateSignature, ev *event) ([]byte, error) {
	sigbytes, err := sig.ToBytes()
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(make([]byte, 0, snapshotLen+signLen+len(sigbytes)))

	buffer.Write(snapshot.Bytes())
	siglen := make([]byte, signLen)
	binary.LittleEndian.PutUint16(siglen, uint16(len(sigbytes)))
	buffer.Write(siglen)
	buffer.Write(sigbytes)

	if ev != nil {
		evsigbytes, err := ev.sig.ToBytes()
		if err != nil {
			return nil, err
		}

		switch ev.kind {
		case replicaJoined:
			buffer.Grow(joinedEventTopicLen + len(evsigbytes))
		case replicaRemoved:
			buffer.Grow(removedEventTopicLen + len(evsigbytes))
		}
		buffer.WriteByte(ev.kind)
		expire := make([]byte, 8)
		binary.LittleEndian.PutUint64(expire, ev.expire)
		buffer.Write(expire)
		buffer.Write(ev.id.Bytes())
		if ev.kind == replicaJoined {
			buffer.Write(ev.pubkey.ToBytes())
		}
		buffer.Write(evsigbytes)
	}

	return buffer.Bytes(), nil
}

func legacyQuorumCertDigest(view uint64, block []byte) (hash common.Hash) {
	viewbytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(viewbytes, view)

	return legacyCypherDigest(viewbytes, block)
}

func legacyCypherDigest(texts ...[]byte) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	for _, text := range texts {
		hasher.Write(text)
	}
	hasher.Sum(hash[:0])
	return
}
