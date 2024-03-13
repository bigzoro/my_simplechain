package hotstuff

import (
	"github.com/simplechain-org/go-simplechain/consensus"
	bls "github.com/simplechain-org/go-simplechain/consensus/hotstuff/bls12-381"
	"github.com/simplechain-org/go-simplechain/consensus/hotstuff/common"
)

// The config to build the Hotstuff consensus engine(council)
type Config struct {
	Mine bool

	Id common.ID

	Key *bls.PrivateKey

	ServiceMaker func(consensus.ChainReader) *Service

	ChainReader consensus.ChainReader
}
