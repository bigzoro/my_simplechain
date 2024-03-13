package raft

import (
	"github.com/bigzoro/my_simplechain/core/types"
)

type InvalidRaftOrdering struct {
	// Current head of the chain
	HeadBlock *types.Block

	// New block that should point to the head, but doesn't
	InvalidBlock *types.Block
}
