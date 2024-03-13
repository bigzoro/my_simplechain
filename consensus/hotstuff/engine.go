package hotstuff

import (
	"errors"
	"math/big"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/common/hexutil"
	"github.com/simplechain-org/go-simplechain/consensus"
	"github.com/simplechain-org/go-simplechain/core/state"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/rlp"
	"github.com/simplechain-org/go-simplechain/rpc"
	"golang.org/x/crypto/sha3"
)

var (
	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	nonceZero = hexutil.MustDecode("0x0000000000000000") // zero nonce
)

var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidDifficulty is returned if the difficulty is not equal to the difference
	// in view between the verified header and its parent header
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidNonce is returned if a nonce value is lower than the parent's one.
	errInvalidNonce = errors.New("invalid nonce")

	// errInvalidSnapshot is returned if there is inconsistent snapshot between the
	// initial snapshot and the snapshot after adding/removing replicas
	errInvalidSnapshot = errors.New("invalid snapshot")
)

// Author implements consensus.Engine.Author and retrieves the Ethereum
// address of the account that minted the given block.
func (lg *Legal) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader implements consensus.Engine.VerifyHeader and checks whether
// a header conforms to the consensus rules of the Hotstuff engine. Verifying
// the seal is done here.
func (lg *Legal) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return lg.verifyHeader(chain, header, nil)
}

// VerifyHeaders implements consensus.Engine.VerifyHeaders, it is similar to
// VerifyHeader, but verifies a batch of headers concurrently. The method
// returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (lg *Legal) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := lg.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles implements consensus.Engine.VerifyUncles and verifies that
// the given block's uncles conform to the consensus rules of Hotstuff engine.
func (lg *Legal) VerifyUncles(ChainReader consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (lg *Legal) VerifySeal(ChainReader consensus.ChainReader, header *types.Header) error {
	return lg.verifySeal(header, ChainReader.GetHeader(header.ParentHash, header.Number.Uint64()-1))
}

// Prepare implements consensus.Engine.Prepare and does nothing.
func (lg *Legal) Prepare(chain consensus.ChainReader, header *types.Header) error {
	header.Difficulty = new(big.Int)
	return nil
}

// Finalize implements consensus.Engine.Finalize.
func (lg *Legal) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) error {
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)
	return nil
}

// FinalizeAndAssemble implements consensus.Engine.FinalizeAndAssemble.
func (lg *Legal) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing.
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal implements consensus.Engine.Seal and does nothing.
func (lg *Legal) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
}

// SealHash implements consensus.Engine.SealHash, returns the hash of a block
// prior to it being sealed.
func (lg *Legal) SealHash(header *types.Header) (hash common.Hash) {
	hashObject := sha3.NewLegacyKeccak256()
	rlp.Encode(hashObject, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.MixDigest,
	})
	hashObject.Sum(hash[:0])
	return hash
}

// CalcDifficulty implements consensus.Engine.CalcDifficulty.
func (lg *Legal) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return new(big.Int)
}

// APIs implements consensus.Engine.APIs.
func (lg *Legal) APIs(chain consensus.ChainReader) []rpc.API {
	return nil
}

// Close implements consensus.Engine.Close.
func (lg *Legal) Close() error {
	return nil
}

func (lg *Legal) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	// Basicly check if the header is extended from its parent.
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrInvalidNumber
	}

	// The block's difficulty represents the number of consensus rounds a block needs to
	// go through before being committed, ensuring that they are strictly equal.
	if header.Difficulty == nil || header.Difficulty.Sign() <= 0 || header.Difficulty.Uint64() != header.Nonce.Uint64()-parent.Nonce.Uint64() {
		return errInvalidDifficulty
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in Hotstuff.
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	if parent.Time >= header.Time {
		return errInvalidTimestamp
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently.
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	return lg.verifySeal(header, parent)
}

func (lg *Legal) verifySeal(header *types.Header, parent *types.Header) error {
	// Recovery the parent block snapshot
	parentSnapHash, _ := extractSnapshot(parent, true)
	snap, err := lg.snapshot(parentSnapHash)
	if err != nil {
		return err
	}

	parentReplicaEvent, _ := extractReplicaEvent(parent, true)
	if parentReplicaEvent != nil {
		snap = parentReplicaEvent.apply(snap)
		if err := lg.store(snap); err != nil {
			return err
		}
	}

	snapHash, sig, ev, err := extract(header)
	if err != nil {
		return err
	}

	if snapHash != snap.Hash() {
		return errInvalidSnapshot
	}

	if ev != nil {
		if err := ev.verify(snap, header.Number.Uint64()); err != nil {
			return err
		}
	}

	// Verify block holds a valid quorum certificate.
	return sig.Verify(snap, legacyQuorumCertDigest(header.Nonce.Uint64()-1, header.ParentHash.Bytes()).Bytes())
}

// Prepare implements consensus.Engine.Prepare, preparing all the consensus fields of the
// header for running the transactions on top. Furthermore, the consensus state of the Council
// will be updated and enter a new consensus round to generate quorum certificates more quickly
// if there are changes in the passed head header.
func (c *Council) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// The preparing header from miner is always based on the chain head block, so
	// there is no need to check if the header is based on the latest block.
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)

	var stateChanged bool
	c.base.mux.RLock()
	if header.ParentHash != c.base.block {
		stateChanged = true
	}
	c.base.mux.RUnlock()

	if stateChanged {
		c.newHead <- parent // Update the consensus state of the Council.
	}

	header.Difficulty = new(big.Int)

	return nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (c *Council) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	parentview := parent.Nonce.Uint64()

	// Use a buffered channel to ensure that the first subscription of an existing
	// quorum certificate is not missed when subscribing.
	certc := make(chan *cert, 1)
	go func() {
		// defer c.taskmngr.optimal.unsub(certc)

		for {
			select {
			case cert, ok := <-certc:
				if !ok {
					log.Debug("Discards sealing for consensus state changed")
					return
				}
				if cert.blockBased != header.ParentHash {
					log.Error("Bad certificate on wrong source", "want", header.ParentHash, "receive", cert.blockBased)
					return
				}

				// Set the value of header nonce field to the view.
				header.Nonce = types.EncodeNonce(cert.view + 1)

				// Set the value of the header difficulty field to the difference between the current
				// view and the view of the parent block.
				header.Difficulty = new(big.Int).SetUint64(cert.view - parentview + 1)

				ev := c.navigation.commit(cert.snap)
				if ev != nil {
					if err := ev.verify(cert.snap, number); err != nil {
						log.Debug("Replica event validation", "id", ev.id, "error", err)
						ev = nil
					}
				}

				// Embed the quorum certificate into the header's extra field.
				extra, err := seal(cert.snap.Hash(), cert.signature, ev)
				if err != nil {
					log.Debug("Failed sealing", "error", err)
					return
				}
				header.Extra = extra

				select {
				case results <- block.WithSeal(header):
				default:
				}

			case <-stop:
				return
			}
		}
	}()

	c.poller.optimal.Subscribe(certc, header.ParentHash)

	return nil
}

// APIs implements Hotstuff engine apis.
func (c *Council) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "hotstuff",
		Version:   "1.0",
		Service:   &API{chain: chain, council: c},
		Public:    false,
	}}
}
