package hotstuff

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/consensus"
	bls "github.com/simplechain-org/go-simplechain/consensus/hotstuff/bls12-381"
	hots "github.com/simplechain-org/go-simplechain/consensus/hotstuff/common"
	hotsptcl "github.com/simplechain-org/go-simplechain/consensus/hotstuff/hotsptcl"
	"github.com/simplechain-org/go-simplechain/core/types"
	logger "github.com/simplechain-org/go-simplechain/log"
	"github.com/simplechain-org/go-simplechain/p2p/enode"
)

var (
	// The maximum acceptable number of consensus phase windows exceeded for the current view.
	maxProcessView uint64 = 1 << 5

	viewPeriod = time.Second * 5 // The duration of each consensus phase window(view).

	log = logger.New("module", "Hotstuff")
)

var (
	// errViewLagged is returned when handling HotStuff messages with a view that is lagging behind.
	errViewLagged = errors.New("event view lags behind the local detemined")

	// errClosed is returned when a HotStuff message processing request is received after
	// the engine has been shut down.
	errEngineClosed = errors.New("Hotstuff engine closed")
)

// expiration records remote timeout events to provide feedback on their events
// when local timeout occurs.
type expiration struct {
	id   hots.ID
	view uint64
}

type expirations []*expiration

func (set expirations) Len() int { return len(set) }

func (set expirations) Swap(i, j int) { set[i], set[j] = set[j], set[i] }

func (set expirations) Less(i, j int) bool {
	return set[i].view < set[j].view
}

// poll collects the agreements of certain consensus phase window from the Hotstuff replicas.
type poll struct {
	done bool

	start time.Time
	view  uint64

	signatures bls.PartialSignatureSet
}

// polls tracks all the progress of vote collections for each consensus window
// in which the local replica acts as the leader.

// The latest poll starts, the oledst one expires.
type polls struct {
	threshold  int
	count      int
	head, rear int
	polls      []poll
}

// reset cleans up all the previous collections and reset the threshold for
// signature aggregation.
func (p *polls) reset(threshold int) {
	for i := 0; i < p.count; i++ {
		index := (p.head + i) % len(p.polls)
		p.polls[index].signatures = nil
	}
	p.threshold = threshold
	p.count, p.head, p.rear = 0, 0, 0
}

// index returns the poll at the given index.
func (p *polls) index(index int) *poll {
	return &p.polls[(p.head+index)%len(p.polls)]
}

// search finds the wanted poll in polls by a given view, and return it's index.
func (p *polls) search(view uint64) (int, bool) {
	i := sort.Search(p.Len(), func(i int) bool {
		return p.polls[(p.head+i)%len(p.polls)].view == view
	})
	return i, i <= p.count && p.polls[(p.head+i)%len(p.polls)].view == view
}

// aggregatable returns if a poll of certain index is aggregatable.
func (p *polls) aggregatable(index int) bool {
	return len(p.index(index).signatures) >= p.threshold
}

// start appends a new poll to the polls, assuming that all newly added polls
// are ordered and increase by view.
func (p *polls) start(view uint64, verified ...*bls.PartialSignature) *poll {
	insert := &p.polls[p.rear]
	insert.start = time.Now()
	insert.view = view
	insert.done = false
	insert.signatures = make(bls.PartialSignatureSet, 0, p.threshold)
	insert.signatures = append(insert.signatures, verified...)
	p.rear = (p.rear + 1) % len(p.polls)
	if p.count >= len(p.polls) {
		p.head = (p.head + 1) % len(p.polls)
	} else {
		p.count++
	}
	return insert
}

func (p *polls) Len() int { return p.count }

func (p *polls) Swap(i, j int) {
	p.polls[(p.head+i)%len(p.polls)], p.polls[(p.head+j)%len(p.polls)] = p.polls[(p.head+j)%len(p.polls)], p.polls[(p.head+i)%len(p.polls)]
}

func (p *polls) Less(i, j int) bool {
	return p.polls[(p.head+i)%len(p.polls)].view < p.polls[(p.head+j)%len(p.polls)].view
}

// cert is the certificate generated after consensus is reached.
type cert struct {
	view       uint64
	blockBased common.Hash
	snap       *snapshot

	signature *bls.AggregateSignature
}

// optimal maintains the prior certificate and publish it to the subscriber.

// If multiple subscribers subscribe to certificates based on the same block, the
// optimal will only publish the corresponding certificate to one of the subscribers.
type optimal struct {
	mux        sync.Mutex
	view       uint64
	blockBased common.Hash
	snap       *snapshot

	signature *bls.AggregateSignature

	sent       uint64
	subscribes map[common.Hash]chan *cert
}

// reset initializes the state on which the optimal certificate is based and clears all
// old subscription.
func (op *optimal) reset(base common.Hash, snap *snapshot) {
	op.mux.Lock()
	defer op.mux.Unlock()

	op.snap = snap
	op.blockBased = base
	op.view = 0
	op.signature = nil
	op.sent = 0

	for sbase, sub := range op.subscribes {
		if sbase != base {
			close(sub)
			delete(op.subscribes, sbase)
		}
	}
}

// update updates the prior certificate.
func (op *optimal) update(poll *poll) {
	op.mux.Lock()
	defer op.mux.Unlock()

	if poll.view <= op.view {
		return
	}
	op.view = poll.view
	op.signature, _ = bls.Combine(poll.signatures...)

	log.Debug("New quorum certificate", "view", op.view, "base", op.blockBased)

	// If there is a certificate subscription on this block, publish this certificate.
	if sub, ok := op.subscribes[op.blockBased]; ok {
		select {
		case sub <- &cert{view: op.view, blockBased: op.blockBased, signature: op.signature.Clone(), snap: op.snap}:
			op.sent = op.view
		default:
		}
	}
}

// Subscribe subscribes the optimal certificate of a certain block and receives the
// certificate at most once.
func (op *optimal) Subscribe(sub chan *cert, base common.Hash) {
	op.mux.Lock()
	defer op.mux.Unlock()

	if op.view > op.sent && op.signature != nil && base == op.blockBased {
		select {
		case sub <- &cert{view: op.view, blockBased: op.blockBased, signature: op.signature.Clone(), snap: op.snap}:
			op.sent = op.view
		default:
		}
	}
	op.subscribes[base] = sub
}

// poller oversees the process of legally generating quorum certificates by actively
// or passively facilitating consensus among HotStuff replicas.
type poller struct {
	current uint64

	expirations expirations
	polls       *polls
	optimal     *optimal

	delayed map[uint64][]*bls.PartialSignature
}

func newPoller() *poller {
	return &poller{
		optimal: &optimal{subscribes: make(map[common.Hash]chan *cert)},
		polls:   &polls{polls: make([]poll, maxProcessView)},
		delayed: make(map[uint64][]*bls.PartialSignature),
	}
}

// Reset starts a new consensus phase window and initialized the based state.
func (poller *poller) Reset(view uint64, base common.Hash, snap *snapshot) {
	poller.current = view
	poller.optimal.reset(base, snap)
	poller.expirations = poller.expirations[:0]

	// Discard all the expired partial signatures cache as the based state has changed.
	poller.polls.reset(snap.Threshold())

	// Clean up the recorded remote timed out events.
	for view := range poller.delayed {
		delete(poller.delayed, view)
	}
}

// Start starts a vote collection task.
func (poller *poller) Start(view uint64) {
	log.Debug("Start collection task", "view", view)

	poll := poller.polls.start(view, poller.delayed[view]...) // with the delayed votes.
	if !poll.done && len(poll.signatures) >= poller.polls.threshold {
		poll.done = true
		poller.optimal.update(poll)

		log.Debug("Finish collection task", "view", poll.view, "elapsed", common.PrettyDuration(time.Since(poll.start)))
	}
	delete(poller.delayed, view)
}

// Expire is an attempt to add a timed out event of a remote replica on a specific view
// to the timed out events queue, and returns whether it's timed out locally on the view.
func (poller *poller) Expire(view uint64, id hots.ID) bool {

	// Process events within the valid range of view (detemined, current+maxProcessExpired).
	if view > poller.current+maxProcessView {
		return false
	}
	if view <= poller.current {
		return true
	}

	i := sort.Search(len(poller.expirations), func(i int) bool { return poller.expirations[i].view == view })
	if i >= len(poller.expirations) || poller.expirations[i].view != view {
		// Insert the unrecorded timed out event.
		poller.expirations = append(poller.expirations, &expiration{id: id, view: view})
		sort.Sort(poller.expirations)
	}
	return false
}

// Collect collects signature votes for the agreement of consensus state transition.
func (poller *poller) Collect(view uint64, sig *bls.PartialSignature) {
	i, ok := poller.polls.search(view)
	if ok {
		poll := poller.polls.index(i)
		if dup(poll.signatures, sig) { // Filter out duplicate signatures.
			return
		}
		poll.signatures = append(poll.signatures, sig)

		// The condition for signature aggregation have been met, and the collection
		// with the highest view can be the optimal source for the future block certificate.
		if !poll.done && poller.polls.aggregatable(i) {
			poll.done = true
			poller.optimal.update(poll)

			log.Debug("Finish collection task", "view", poll.view, "elapsed", common.PrettyDuration(time.Since(poll.start)))
		}

	} else {
		if !dup(poller.delayed[view], sig) { // Filter out duplicate signatures.
			poller.delayed[view] = append(poller.delayed[view], sig)
		}
	}
}

// Forward increases the current view and returns the triggered remote replica timed out events.
func (poller *poller) Forward() (uint64, expirations) {
	poller.current++
	remove := make(expirations, 0, 1)
	for i := 0; i < len(poller.expirations) && poller.expirations[i].view <= poller.current; i++ {
		remove = append(remove, poller.expirations[i])
	}
	if len(remove) > 0 {
		poller.expirations = append(poller.expirations[:0], poller.expirations[len(remove):]...)
	}

	return poller.current, remove
}

// vote ancapsulates a vote event from a remote replica.
type vote struct {
	id   hots.ID
	view uint64

	// The vote event includes block information, which helps prevent the failure
	// of valid vote message verification due to delayed reception of proposal messages.
	block     []byte
	signature *bls.PartialSignature
}

// timeout ancapsulates a timed out event from a remote replica.
type timeout struct {
	id   hots.ID
	view uint64
}

// transmition is responsible for sending or broadcasting messages to the corresponding
// replicas during the HotStuff consensus process.
type transmition interface {
	protocol

	Timeout(view uint64) error
	Vote(remote hots.ID, view uint64, block common.Hash, sig *bls.PartialSignature) error

	GetEnode(ids []hots.ID) []enode.ID
}

type base struct {
	mux   sync.RWMutex
	block common.Hash

	snap       *snapshot
	determined uint64
}

// Council is the Hotstuff consensus engine.
type Council struct {
	*Legal

	ctx    context.Context
	cancel context.CancelFunc

	// The identity for the local Hotstuff replica.
	id  hots.ID
	key *bls.PrivateKey

	// The initial state at the beginning of each round of consensus.
	base base

	// The events that drive the state transition in HotStuff.
	newHead     chan *types.Header
	vote        chan *vote
	timeout     chan *timeout
	transmition transmition

	poller  *poller
	delayed map[uint64][]*vote

	navigation *navigation
}

func NewCouncil(lg *Legal, id hots.ID, key *bls.PrivateKey) *Council {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Council{
		Legal: lg,

		ctx:        ctx,
		cancel:     cancel,
		id:         id,
		key:        key,
		newHead:    make(chan *types.Header),
		vote:       make(chan *vote),
		timeout:    make(chan *timeout),
		delayed:    make(map[uint64][]*vote),
		poller:     newPoller(),
		navigation: newNavigation(),
	}
	hub := hotsptcl.NewHub(c)
	c.transmition = hub

	go c.schedule(ctx)

	return c
}

// MakeService returns Hotstuff protocol handler service which implements node.Service.
// Note, the method should only be called once during the registration of an Ethereum
// node service.
func (c *Council) MakeService(chain consensus.ChainReader) *Service {
	return &Service{protocol: c.transmition, chain: chain}
}

// Verify verifies the validity of a partial signature.
func (c *Council) VerifyAt(header *types.Header, sig *bls.PartialSignature, text []byte) error {
	snaphash, _ := extractSnapshot(header, true)

	snap, err := c.snapshot(snaphash)
	if err != nil {
		return err
	}

	return sig.Verify(snap, text)
}

// Sign signs the ciphertext using the local private key
func (c *Council) Sign(text []byte) (*bls.PartialSignature, error) {
	return c.key.SignWithId(text, c.id)
}

// Vote notifies the council of the remote voting events.
func (c *Council) Vote(id hots.ID, view uint64, block []byte, sig *bls.PartialSignature) error {
	select {
	case c.vote <- &vote{id: id, view: view, block: block, signature: sig}:
	case <-c.ctx.Done():
		return errEngineClosed
	}
	return nil
}

// Timeout notifies the council of the remote timed out events.
func (c *Council) Timeout(id hots.ID, view uint64) error {
	select {
	case c.timeout <- &timeout{id: id, view: view}:
	case <-c.ctx.Done():
		return errEngineClosed
	}
	return nil
}

// Prior implements handler.priorBroadcastSelector to choose the prior peers for
// broadcasting the block.
func (c *Council) Prior(block *types.Block) []enode.ID {
	snap, err := c.snapshot(common.BytesToHash(block.Header().Extra[:snapshotLen]))
	if err != nil {
		return nil
	}

	view := block.Header().Nonce.Uint64()
	peers := make([]hots.ID, 0, snap.Threshold()-1)
	for len(peers) < cap(peers) {
		peers = append(peers, snap.Leader(view, c.rot))
		view++
	}

	return c.transmition.GetEnode(peers)
}

func (c *Council) Close() error {
	c.cancel()
	c.transmition.Close()
	return nil
}

// schedule is responsible for synchronizing the view state with remote nodes and managing
// its own view state machine. Additionally, A takes charge with vote collection to generate
// quorum certificates for proposing blocks.
func (c *Council) schedule(ctx context.Context) {
	timer := time.NewTimer(viewPeriod)
loop:
	for {
		select {
		case header := <-c.newHead:
			if err := c.onPropose(header); err != nil {
				log.Error("Process proposal", "error", err)
			}

			timer.Reset(viewPeriod)

		case timeout := <-c.timeout:
			if c.base.snap == nil {
				continue loop
			}
			if err := c.checkTimeout(timeout); err != nil {
				log.Debug("Disard remote timeout event", "error", err, "peer", timeout.id, "view", timeout.view)
				continue loop
			}

			if c.poller.Expire(timeout.view, timeout.id) {
				sig, err := c.sign(timeout.view, c.base.block.Bytes())
				if err == nil {
					c.transmition.Vote(timeout.id, timeout.view, c.base.block, sig)
				}
			}

		case vote := <-c.vote:
			if c.base.snap == nil || !bytes.Equal(vote.block, c.base.block.Bytes()) {
				log.Debug("Add vote for future", "view", vote.view, "id", vote.id, "base", common.BytesToHash(vote.block), "want", c.base.block)
				c.delayed[vote.view] = append(c.delayed[vote.view], vote)
				continue loop
			}

			// Receive votes based on same proposal.

			if err := c.checkVote(vote); err != nil {
				log.Debug("Invalid vote event", "error", err, "peer", vote.id, "view", vote.view)
				continue loop
			}

			log.Debug("Receive vote", "view", vote.view, "id", vote.id, "base", common.BytesToHash(vote.block))
			c.poller.Collect(vote.view, vote.signature)

		case <-timer.C:
			if err := c.onTimeout(); err != nil {
				log.Error("Process local timeout", "error", err)
			}
			timer.Reset(viewPeriod)

		case <-ctx.Done():
			return
		}
	}
}

// onPropose processes incoming proposals.
func (c *Council) onPropose(header *types.Header) error {
	snap, err := c.snapshot(common.BytesToHash(header.Extra[:snapshotLen]))
	if err != nil {
		return err
	}
	if ev, _ := extractReplicaEvent(header, true); ev != nil {
		snap = ev.apply(snap)
		if err := c.store(snap); err != nil {
			return err
		}
	}

	view := header.Nonce.Uint64()
	hash := header.Hash()

	c.base.mux.Lock()
	c.base.determined = view - 1
	c.base.block = hash
	c.base.snap = snap
	c.base.mux.Unlock()

	log.Debug("Based on new consensus state", "number", header.Number.Uint64(), "hash", hash)
	// todo handle parent block extra event(add HotStuff peer)

	// Reset the task manager to be based on the latest consensus canonical block.
	c.poller.Reset(view, hash, snap)

	defer func() {
		for view := range c.delayed {
			if view <= c.base.determined {
				delete(c.delayed, view)
			}
		}
	}()

	// todo emit HotStuff block event

	leader := snap.Leader(view, c.rot)
	if c.id != leader {
		// Sign the proposal block and send the vote.
		sig, err := c.sign(view, hash.Bytes())
		if err != nil {
			return err
		}
		return c.transmition.Vote(leader, view, hash, sig)
	}

	// If I am the leader for the next round, fulfill the obligation of collecting
	// votes for this round.
	c.poller.Start(view)

	// Validate and add delayed votes that belonging to this new collection task.
	delayed := c.delayed[view]
	for _, vote := range delayed {
		if !bytes.Equal(vote.block, hash.Bytes()) {
			continue
		}
		if err := c.checkVote(vote); err != nil {
			log.Debug("Invalid vote event", "error", err, "peer", vote.id, "view", vote.view)
			continue
		}

		c.poller.Collect(vote.view, vote.signature)
	}

	// Involves the partial signature signed by leader.
	sig, err := c.sign(view, hash.Bytes())
	if err != nil {
		return err
	}
	c.poller.Collect(view, sig)

	return nil
}

// onTimeout handles or responds to local or remote timeout events
func (c *Council) onTimeout() error {
	if c.base.snap == nil {
		return nil
	}

	cur, exprs := c.poller.Forward()

	log.Debug("Local time out", "view", cur-1)
	if c.base.snap.Leader(cur, c.rot) == c.id {
		sig, err := c.sign(cur, c.base.block.Bytes())
		if err != nil {
			return err
		}
		c.poller.Start(cur)
		c.poller.Collect(cur, sig)
		c.transmition.Timeout(cur)

	} else {
		for i := range exprs {
			sig, err := c.sign(exprs[i].view, c.base.block.Bytes())
			if err != nil {
				return nil
			}
			c.transmition.Vote(exprs[i].id, exprs[i].view, c.base.block, sig)
		}
	}

	return nil
}

func (c *Council) checkTimeout(event *timeout) error {
	if event.view <= c.base.determined {
		return errViewLagged
	}

	if event.id != c.base.snap.Leader(event.view, c.rot) {
		return errors.New("not leader")
	}
	return nil
}

func (c *Council) checkVote(event *vote) error {
	if event.view <= c.base.determined {
		return errViewLagged
	}

	return event.signature.Verify(c.base.snap, legacyQuorumCertDigest(event.view, event.block).Bytes())
}

func (c *Council) sign(view uint64, block []byte) (*bls.PartialSignature, error) {
	return c.key.SignWithId(legacyQuorumCertDigest(view, block).Bytes(), c.id)
}

// duplicate signatures check when there are few signatures.
func dup(origin []*bls.PartialSignature, new *bls.PartialSignature) bool {
	for _, sig := range origin {
		if sig.ID() == new.ID() {
			return true
		}
	}
	return false
}
