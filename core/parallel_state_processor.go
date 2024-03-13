// Copyright 2020 The go-simplechain Authors
// This file is part of the go-simplechain library.
//
// The go-simplechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-simplechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-simplechain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"time"

	"github.com/simplechain-org/go-simplechain/consensus"
	"github.com/simplechain-org/go-simplechain/core/state"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/core/vm"
	"github.com/simplechain-org/go-simplechain/log"
	"github.com/simplechain-org/go-simplechain/params"
)

type ParallelStateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

func NewParallelStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *ParallelStateProcessor {
	return &ParallelStateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

func (p *ParallelStateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*types.Header, types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	// Iterate over and process the individual transactions
	if len(block.Transactions()) > 0 {
		start := time.Now()
		ctx := NewParallelContext(statedb, header, block.Hash(), gp, false, GetExecutor().Signer())
		ctx.SetBlockGasUsedHolder(usedGas)
		ctx.SetTxList(block.Transactions())
		if err := GetExecutor().ExecuteTransactions(ctx); err != nil {
			return nil, nil, nil, 0, err
		}
		receipts = ctx.GetReceipts()
		allLogs = ctx.GetLogs()
		log.Trace("Process parallel execute transactions cost time", "blockNumber", block.Number(), "blockHash", block.Hash().Hex(), "time", time.Since(start))
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), nil, receipts)
	return header, receipts, allLogs, *usedGas, nil
}
