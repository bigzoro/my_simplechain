package hotstuff

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bigzoro/my_simplechain/common/hexutil"
	"github.com/bigzoro/my_simplechain/consensus"
	bls "github.com/bigzoro/my_simplechain/consensus/hotstuff/bls12-381"
	"github.com/bigzoro/my_simplechain/consensus/hotstuff/common"
	"github.com/bigzoro/my_simplechain/rpc"
)

type replica struct {
	ID     uint32
	Pubkey hexutil.Bytes
}

// API is a user facing RPC API to send requests for replicas joining/removing to the
// Hotstuff network
type API struct {
	chain   consensus.ChainReader
	council *Council
}

func (api *API) Add(expire rpc.BlockNumber, id uint32, pkbytes hexutil.Bytes, sigbytes hexutil.Bytes) error {
	if header := api.chain.CurrentHeader(); uint64(expire) <= header.Number.Uint64() {
		return fmt.Errorf("expired event for %d/%d", expire, header.Number.Uint64())
	}

	ev := &event{
		kind:   replicaJoined,
		expire: uint64(expire),
	}
	ev.id.SetUint32(id)
	ev.pubkey = new(bls.PublicKey)
	if err := ev.pubkey.FromBytes(pkbytes); err != nil {
		return err
	}
	ev.sig = new(bls.AggregateSignature)
	if err := ev.sig.FromBytes(sigbytes); err != nil {
		return err
	}
	return api.council.navigation.add(ev)
}

func (api *API) Remove(expire rpc.BlockNumber, id uint32, sigbytes hexutil.Bytes) error {
	if header := api.chain.CurrentHeader(); uint64(expire) <= header.Number.Uint64() {
		return fmt.Errorf("expired event for %d/%d", expire, header.Number.Uint64())
	}

	ev := &event{
		kind:   replicaRemoved,
		expire: uint64(expire),
	}
	ev.id.SetUint32(id)
	ev.sig = new(bls.AggregateSignature)
	if err := ev.sig.FromBytes(sigbytes); err != nil {
		return err
	}
	return api.council.navigation.add(ev)
}

func (api *API) ProposeAdd(expire rpc.BlockNumber, id uint32, pkbytes hexutil.Bytes) (hexutil.Bytes, error) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, uint64(expire))

	hotsid := new(common.ID)
	hotsid.SetUint32(id)

	sig, err := api.council.Sign(legacyCypherDigest([]byte{replicaJoined}, raw, hotsid.Bytes(), pkbytes).Bytes())
	if err != nil {
		return nil, err
	}
	return sig.ToBytes()
}

func (api *API) ProposeRemove(expire rpc.BlockNumber, id uint32) (hexutil.Bytes, error) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, uint64(expire))

	hotsid := new(common.ID)
	hotsid.SetUint32(id)

	sig, err := api.council.Sign(legacyCypherDigest([]byte{replicaRemoved}, raw, hotsid.Bytes()).Bytes())
	if err != nil {
		return nil, err
	}
	return sig.ToBytes()
}

func (api *API) GetReplicaInfo(expire rpc.BlockNumber) ([]replica, error) {
	header := api.chain.GetHeaderByNumber(uint64(expire))
	if header == nil {
		return nil, errors.New("unknown block")
	}

	snaphash, err := extractSnapshot(header, true)
	if err != nil {
		return nil, err
	}
	snap, err := api.council.snapshot(snaphash)
	if err != nil {
		return nil, err
	}

	reps := make([]replica, 0, len(snap.Idset))
	for i := range snap.Idset {
		reps = append(reps, replica{
			ID:     snap.Idset[i].Uint32(),
			Pubkey: hexutil.Bytes(snap.Pubkeys[snap.Idset[i]].ToBytes()),
		})
	}

	return reps, nil
}

func (api *API) Aggregate(mulSigbytes []hexutil.Bytes) (hexutil.Bytes, error) {
	sigs := make([]*bls.PartialSignature, 0, len(mulSigbytes))
	for _, sigbytes := range mulSigbytes {
		sig := new(bls.PartialSignature)
		if err := sig.FromBytes(sigbytes); err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}

	aggr, err := bls.Combine(sigs...)
	if err != nil {
		return nil, err
	}
	return aggr.ToBytes()
}
