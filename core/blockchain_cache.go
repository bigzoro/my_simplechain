// Copyright 2018-2020 The PlatON Network Authors
// This file is part of the PlatON-Go library.
//
// The PlatON-Go library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The PlatON-Go library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the PlatON-Go library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/consensus"
	"github.com/bigzoro/my_simplechain/core/state"
	"github.com/bigzoro/my_simplechain/core/types"
	"github.com/bigzoro/my_simplechain/log"
)

var (
	errMakeStateDB = errors.New("make StateDB error")
)

type BlockChainCache struct {
	*BlockChain
	stateDBCache  map[common.Hash]*stateDBCache  // key is header SealHash
	receiptsCache map[common.Hash]*receiptsCache // key is header SealHash
	blockCache    map[common.Hash]*types.Block
	stateDBMu     sync.RWMutex
	receiptsMu    sync.RWMutex
	blockMu       sync.RWMutex

	executing sync.Mutex
	//executed  sync.Map
}

type stateDBCache struct {
	stateDB  *state.StateDB
	blockNum uint64
}

type receiptsCache struct {
	usedGas uint64
	//logs     []*types.Log
	receipts []*types.Receipt
	blockNum uint64
}

func NewBlockChainCache(blockChain *BlockChain) *BlockChainCache {
	pbc := &BlockChainCache{}
	pbc.BlockChain = blockChain
	pbc.stateDBCache = make(map[common.Hash]*stateDBCache)
	pbc.receiptsCache = make(map[common.Hash]*receiptsCache)
	pbc.blockCache = make(map[common.Hash]*types.Block)

	return pbc
}

func (bcc *BlockChainCache) GetPendingBlock(hash common.Hash) *types.Block {
	if pbft, ok := bcc.engine.(consensus.Pbft); ok {
		if current := pbft.GetCurrentBlock(); current != nil && current.Hash() == hash {
			return current
		}
	}
	return nil
}

func (bcc *BlockChainCache) ReadBlock(sealHash common.Hash) *types.Block {
	bcc.blockMu.RLock()
	defer bcc.blockMu.RUnlock()
	return bcc.blockCache[sealHash]
}

// Read the Receipt collection from the cache map.
func (bcc *BlockChainCache) ReadReceipts(sealHash common.Hash) (uint64, []*types.Receipt) {
	bcc.receiptsMu.RLock()
	defer bcc.receiptsMu.RUnlock()
	if obj, exist := bcc.receiptsCache[sealHash]; exist {
		return obj.usedGas, obj.receipts //, obj.logs
	}
	return 0, nil
}

// Read the StateDB instance from the cache map
func (bcc *BlockChainCache) ReadStateDB(sealHash common.Hash) *state.StateDB {
	bcc.stateDBMu.RLock()
	defer bcc.stateDBMu.RUnlock()
	log.Debug("Read a StateDB instance", "sealHash", sealHash.String())
	if obj, exist := bcc.stateDBCache[sealHash]; exist {
		return obj.stateDB
	}
	return nil
}

// Write Receipt to the cache
func (bcc *BlockChainCache) WriteReceipts(sealHash common.Hash, usedGas uint64, receipts []*types.Receipt, blockNum uint64) {
	bcc.receiptsMu.Lock()
	defer bcc.receiptsMu.Unlock()
	_, exist := bcc.receiptsCache[sealHash]
	if !exist {
		bcc.receiptsCache[sealHash] = &receiptsCache{usedGas: usedGas, receipts: receipts, blockNum: blockNum}
	}
}

// Write a StateDB instance to the cache
func (bcc *BlockChainCache) WriteStateDB(sealHash common.Hash, stateDB *state.StateDB, blockNum uint64) {
	bcc.stateDBMu.Lock()
	defer bcc.stateDBMu.Unlock()
	log.Debug("Write a StateDB instance to the cache", "sealHash", sealHash.String(), "blockNum", blockNum)
	if _, exist := bcc.stateDBCache[sealHash]; !exist {
		bcc.stateDBCache[sealHash] = &stateDBCache{stateDB: stateDB, blockNum: blockNum}
	}
}

func (bcc *BlockChainCache) WriteSealBlock(sealHash common.Hash, block *types.Block) {
	bcc.blockMu.Lock()
	defer bcc.blockMu.Unlock()
	if _, exist := bcc.blockCache[sealHash]; !exist {
		bcc.blockCache[sealHash] = block
	}
}

// Read the Receipt collection from the cache map
func (bcc *BlockChainCache) clearReceipts(sealHash common.Hash) {
	bcc.receiptsMu.Lock()
	defer bcc.receiptsMu.Unlock()

	//var blockNum uint64
	if obj, exist := bcc.receiptsCache[sealHash]; exist {
		//blockNum = obj.blockNum
		log.Debug("Clear Receipts", "sealHash", sealHash, "number", obj.blockNum)
		delete(bcc.receiptsCache, sealHash)
	}
}

// Read the StateDB instance from the cache map
func (bcc *BlockChainCache) clearStateDB(sealHash common.Hash) {
	bcc.stateDBMu.Lock()
	defer bcc.stateDBMu.Unlock()

	if obj, exist := bcc.stateDBCache[sealHash]; exist {
		//obj.stateDB.ClearReference()
		log.Debug("Clear StateDB", "sealHash", sealHash, "number", obj.blockNum)
		delete(bcc.stateDBCache, sealHash)
		//delete(pbc.stateDBCache, sealHash)
	}
}

func (bcc *BlockChainCache) clearBlock(sealHash common.Hash) {
	bcc.blockMu.Lock()
	defer bcc.blockMu.Unlock()
	delete(bcc.blockCache, sealHash)
}

func (bcc *BlockChainCache) CommitBlock(block *types.Block) {
	bcc.clearCache(block)
}

// Get the StateDB instance of the corresponding block
func (bcc *BlockChainCache) clearCache(block *types.Block) {
	baseNumber := block.NumberU64()
	if baseNumber < 1 {
		return
	}
	log.Debug("Clear cache", "baseBlockHash", block.Hash(), "baseBlockNumber", baseNumber)

	var sh sealHashSort
	bcc.blockMu.RLock()
	for sealHash, block := range bcc.blockCache {
		if block.NumberU64() < baseNumber {
			sh = append(sh, &sealHashNumber{number: baseNumber, hash: sealHash})
		}
	}
	bcc.blockMu.RUnlock()

	for _, s := range sh {
		log.Debug("Clear Cache block", "sealHash", s.hash, "number", s.number)
		bcc.clearReceipts(s.hash)
		bcc.clearStateDB(s.hash)
		bcc.clearBlock(s.hash)
	}
}

func (bcc *BlockChainCache) StateDBString() string {
	status := fmt.Sprintf("[")
	for hash, obj := range bcc.stateDBCache {
		status += fmt.Sprintf("[%s, %d]", hash, obj.blockNum)
	}
	status += fmt.Sprintf("]")
	return status
}

func (bcc *BlockChainCache) Execute(block *types.Block) (*types.Block, error) {
	sealHash := block.PendingHash()
	parent := bcc.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("ancestor block is not exist, parent:%s", block.ParentHash().String())
	}
	executed := func() (bool, *types.Block) {
		bcc.blockMu.RLock()
		defer bcc.blockMu.RUnlock()
		if b, ok := bcc.blockCache[sealHash]; ok && (block.NumberU64() == b.NumberU64()) {
			log.Debug("Block has executed", "number", block.Number(), "hash", block.Hash(), "parentNumber", parent.Number, "parentHash", parent.Hash())
			return true, b
		}
		return false, nil
	}

	if ok, b := executed(); ok {
		return b, nil
	}

	bcc.executing.Lock()
	defer bcc.executing.Unlock()
	if ok, b := executed(); ok {
		return b, nil
	}
	log.Debug("Start execute block", "hash", block.Hash(), "number", block.Number(), "sealHash", block.PendingHash())
	start := time.Now()
	statedb, err := state.New(parent.Root, bcc.StateCache())
	elapse := time.Since(start)
	if err != nil {
		return nil, errors.New("execute block error")
	}

	t := time.Now()
	// process block transaction
	newHeader, receipts, _, usedGas, err := bcc.processor.Process(block, statedb, bcc.vmConfig)
	if err != nil {
		log.Error("Failed to Process block", "blockNumber", block.Number(), "blockHash", block.Hash().Hex(), "err", err)
		bcc.reportBlock(block, receipts, err)
		return nil, err
	}

	log.Debug("Execute block", "number", block.Number(), "hash", block.Hash(),
		"parentNumber", parent.Number, "parentHash", parent.Hash(), "duration", time.Since(t), "makeState", elapse, "err", err)

	newHeader.GasUsed = usedGas
	newHeader.Bloom = types.CreateBloom(receipts)
	newHeader.ReceiptHash = types.DeriveSha(receipts)

	block = block.WithSeal(newHeader)
	hash := block.Hash()

	for i, receipt := range receipts {
		// add block location fields
		receipt.BlockHash = hash
		receipt.BlockNumber = block.Number()
		receipt.TransactionIndex = uint(i)
		receipts[i] = receipt
	}

	bcc.WriteReceipts(sealHash, usedGas, receipts, block.NumberU64())
	bcc.WriteStateDB(sealHash, statedb, block.NumberU64())
	bcc.WriteSealBlock(sealHash, block)
	return block, nil
}

func (bcc *BlockChainCache) WriteBlock(block *types.Block) error {
	sealHash := block.PendingHash()
	hash := block.Hash()
	state := bcc.ReadStateDB(sealHash)
	_, receipts := bcc.ReadReceipts(sealHash)

	if state == nil {
		log.Error("Write Block error, state is nil", "number", block.NumberU64(), "hash", block.Hash())
		return fmt.Errorf("write Block error, state is nil, number:%d, hash:%s", block.NumberU64(), block.Hash().String())
	} else if len(block.Transactions()) > 0 && len(receipts) == 0 {
		log.Error("Write Block error, block has transactions but receipts is nil", "number", block.NumberU64(), "hash", block.Hash())
		return fmt.Errorf("write Block error, block has transactions but receipts is nil, number:%d, hash:%s", block.NumberU64(), block.Hash().String())
	}

	var logs []*types.Log
	for _, receipt := range receipts {
		// Update the block hash in all logs since it is now available and not when the
		// receipt/log of individual transactions were created.
		for _, log := range receipt.Logs {
			log.BlockHash = hash
		}
		logs = append(logs, receipt.Logs...)
	}

	// Commit block and state to database.
	_, err := bcc.WriteBlockWithState(block, receipts, logs, state, true)
	if err != nil {
		log.Error("Failed writing block to chain", "hash", block.Hash(), "number", block.NumberU64(), "err", err)
		return fmt.Errorf("failed writing block to chain, number:%d, hash:%s, err:%s", block.NumberU64(), block.Hash().String(), err.Error())
	}

	log.Info("Successfully write new block", "hash", block.Hash(), "number", block.NumberU64())
	return nil
}

type sealHashNumber struct {
	number uint64
	hash   common.Hash
}

type sealHashSort []*sealHashNumber

func (self sealHashSort) Len() int { return len(self) }
func (self sealHashSort) Swap(i, j int) {
	self[i], self[j] = self[j], self[i]
}
func (self sealHashSort) Less(i, j int) bool { return self[i].number < self[j].number }
