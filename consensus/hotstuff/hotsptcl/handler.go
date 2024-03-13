package hotstuffprotocol

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/consensus"
	bls "github.com/bigzoro/my_simplechain/consensus/hotstuff/bls12-381"
	hots "github.com/bigzoro/my_simplechain/consensus/hotstuff/common"
	"github.com/bigzoro/my_simplechain/core/types"
	"github.com/bigzoro/my_simplechain/log"
	"github.com/bigzoro/my_simplechain/p2p"
	"github.com/bigzoro/my_simplechain/p2p/enode"
)

var (
	errNotLegalPeer      = errors.New("not a legal hotstuff peer")
	errAlreadyRegistered = errors.New("replica is already registered")
	errClosed            = errors.New("relica hub is closed")

	handshakeTimeoutRTT = 5 * time.Second

	// handshakeValidatorLen is the fixed length of the authentication random number.
	// used during handshake
	handshakeValidatorLen = 256
)

// handler handles Hotstuff protocol request messages.
type handler interface {
	Timeout(id hots.ID, view uint64) error

	Vote(id hots.ID, view uint64, block []byte, sig *bls.PartialSignature) error
}

type replica struct {
	id      hots.ID
	handler handler

	peer *p2p.Peer
	rw   p2p.MsgReadWriter

	queued chan *timeoutMsg
	quit   chan struct{}
}

func newReplica(id hots.ID, peer *p2p.Peer, rw p2p.MsgReadWriter) *replica {
	return &replica{
		peer:   peer,
		rw:     rw,
		id:     id,
		queued: make(chan *timeoutMsg),
		quit:   make(chan struct{}),
	}
}

func (rep *replica) handle() error {
	msg, err := rep.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > protocolMaxMsgSize {
		return fmt.Errorf("too large message,%d - %d", msg.Size, protocolMaxMsgSize)
	}
	defer msg.Discard()

	switch msg.Code {
	case vote:
		var vote voteMsg
		if err := msg.Decode(&vote); err != nil {
			return fmt.Errorf("msg %v: %v", msg, err)
		}
		sig := new(bls.PartialSignature)
		if err := sig.FromBytes(vote.Signature); err != nil {
			return fmt.Errorf("signature deserialization:%v", err)
		}
		if err := rep.handler.Vote(rep.id, vote.View, vote.Hash.Bytes(), sig); err != nil {
			rep.peer.Log().Error("handle vote request", "error", err)
		}

	case timeout:
		var timeout timeoutMsg
		if err := msg.Decode(&timeout); err != nil {
			return fmt.Errorf("msg %v: %v", msg, err)
		}
		if err := rep.handler.Timeout(rep.id, timeout.View); err != nil {
			rep.peer.Log().Error("handle timeout request", "error", err)
		}

	default:
		return fmt.Errorf("invalid message code %d", msg.Code)
	}
	return nil
}

func (rep *replica) run(ctx context.Context) {
	for {
		select {
		case msg := <-rep.queued:
			p2p.Send(rep.rw, timeout, msg)

		case <-ctx.Done():
			return
		case <-rep.quit:
			return
		}
	}
}

func (rep *replica) close() error {
	close(rep.quit)
	return nil
}

type identifier interface {
	Sign([]byte) (*bls.PartialSignature, error)

	VerifyAt(*types.Header, *bls.PartialSignature, []byte) error
}

type engine interface {
	identifier
	handler
}

// Hub manages the lifecycle of all connected Hotstuff peers.
type Hub struct {
	closed bool

	ctx    context.Context
	cancel context.CancelFunc

	mux    sync.RWMutex
	peers  map[hots.ID]*replica
	enodes map[hots.ID]enode.ID

	engine engine

	wg sync.WaitGroup
}

func NewHub(engine engine) *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		ctx:    ctx,
		cancel: cancel,
		engine: engine,
		peers:  make(map[hots.ID]*replica),
		enodes: make(map[hots.ID]enode.ID),
	}
}

func (hub *Hub) Vote(remote hots.ID, view uint64, block common.Hash, sig *bls.PartialSignature) error {
	hub.mux.RLock()
	defer hub.mux.RUnlock()

	if hub.closed {
		return errClosed
	}

	peer, ok := hub.peers[remote]
	if !ok {
		return fmt.Errorf("unknown peer %v", remote)
	}
	sigbytes, _ := sig.ToBytes()
	return p2p.Send(peer.rw, vote, &voteMsg{
		View:      view,
		Hash:      block,
		Signature: sigbytes,
	})
}

func (hub *Hub) GetEnode(ids []hots.ID) []enode.ID {
	hub.mux.RLock()
	defer hub.mux.RUnlock()

	enodes := make([]enode.ID, 0, len(ids))
	for i := range ids {
		if enodeId, ok := hub.enodes[ids[i]]; ok {
			enodes = append(enodes, enodeId)
		}
	}
	return enodes
}

func (hub *Hub) Timeout(view uint64) error {
	hub.mux.RLock()
	defer hub.mux.RUnlock()

	if hub.closed {
		return errClosed
	}

	for _, peer := range hub.peers {
		select {
		case peer.queued <- &timeoutMsg{View: view}:
		case <-peer.quit:
		}
	}

	return nil
}

func (hub *Hub) Close() error {
	hub.cancel()

	hub.mux.Lock()
	for _, replica := range hub.peers {
		replica.peer.Disconnect(p2p.DiscQuitting)
	}
	hub.closed = true
	hub.mux.Unlock()

	hub.wg.Wait()
	log.Info("Hotstuff protocol handler stop")

	return nil
}

func (hub *Hub) Handle(peer *p2p.Peer, rw p2p.MsgReadWriter, chain consensus.ChainReader) error {
	id, err := hub.handshake(peer, rw, chain)
	if err != nil {
		peer.Log().Debug("peer handshake failed", "error", err)
		return err
	}
	replica := newReplica(id, peer, rw)
	if err := hub.register(replica); err != nil {
		return err
	}
	defer hub.unregister(replica.id)

	hub.wg.Add(1)
	defer hub.wg.Done()

	peer.Log().Info("hotstuff peer connected", "peer", peer.Name())

	// Handle incoming messages until the connection is torn down
	for {
		if err := replica.handle(); err != nil {
			peer.Log().Debug("hotstuff message handling failed", "err", err)
			return err
		}
	}
}

// Handshake executes the hotstuff protocol handshake
func (hub *Hub) handshake(peer *p2p.Peer, rw p2p.MsgReadWriter, chain consensus.ChainReader) (id hots.ID, err error) {

	// 1.exchange random seed
	// 2.exchange authentication signature

	errc := make(chan error)
	idch := make(chan hots.ID)

	go func() {
		if id, err := hub.checkHandshake(rw, chain); err != nil {
			errc <- err
		} else {
			idch <- id
		}
	}()

	timeout := time.NewTimer(2 * handshakeTimeoutRTT)
	defer timeout.Stop()

	select {
	case id := <-idch:
		return id, nil
	case err := <-errc:
		return hots.ID{}, err
	case <-timeout.C:
		return hots.ID{}, p2p.DiscReadTimeout
	}
}

func (hub *Hub) checkHandshake(rw p2p.MsgReadWriter, chain consensus.ChainReader) (hots.ID, error) {
	seed := make([]byte, handshakeValidatorLen)
	rand.Read(seed)
	if err := p2p.Send(rw, status, &handshakeData{Random: seed}); err != nil {
		return hots.ID{}, err
	}

	validator, err := readLegacy(rw)
	if err != nil {
		return hots.ID{}, err
	}

	if len(validator.Random) != handshakeValidatorLen {
		return hots.ID{}, errors.New("invalid handshake params")
	}

	sig, _ := hub.engine.Sign(validator.Random)
	sigbytes, _ := sig.ToBytes()
	if err := p2p.Send(rw, status, &handshakeData{Signature: sigbytes}); err != nil {
		return hots.ID{}, err
	}

	if validator, err = readLegacy(rw); err != nil {
		return hots.ID{}, err
	}
	if err = sig.FromBytes(validator.Signature); err != nil {
		return hots.ID{}, err
	}

	if err = hub.engine.VerifyAt(chain.CurrentHeader(), sig, seed); err != nil {
		return hots.ID{}, err
	}

	log.Debug("Hotstuff handshake", "id", sig.ID())
	return sig.ID(), nil
}

func (hub *Hub) register(rep *replica) error {
	hub.mux.Lock()
	defer hub.mux.Unlock()

	if hub.closed {
		return errClosed
	}
	if _, ok := hub.peers[rep.id]; ok {
		return errAlreadyRegistered
	}

	hub.peers[rep.id] = rep
	hub.enodes[rep.id] = rep.peer.ID()
	rep.handler = hub.engine
	go rep.run(hub.ctx)

	return nil
}

func (hub *Hub) unregister(id hots.ID) error {
	hub.mux.Lock()
	defer hub.mux.Unlock()

	if rep, ok := hub.peers[id]; ok {
		delete(hub.peers, id)
		delete(hub.enodes, id)
		rep.close()
	}

	return nil
}

func readLegacy(rw p2p.MsgReadWriter) (*handshakeData, error) {
	msg, err := rw.ReadMsg()
	if err != nil {
		return nil, err
	}

	if msg.Code != status {
		return nil, fmt.Errorf("first msg has code %x (!= %x)", msg.Code, status)
	}
	if msg.Size > protocolMaxMsgSize {
		return nil, fmt.Errorf("too large message,%d - %d", msg.Size, protocolMaxMsgSize)
	}
	var status handshakeData
	return &status, msg.Decode(&status)
}
