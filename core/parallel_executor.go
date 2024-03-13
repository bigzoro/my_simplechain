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
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/core/state"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/core/vm"
	"github.com/simplechain-org/go-simplechain/internal/debug"
	"github.com/simplechain-org/go-simplechain/log"
	"github.com/simplechain-org/go-simplechain/params"

	"github.com/exascience/pargo/parallel"
	"github.com/hashicorp/golang-lru"
	"github.com/panjf2000/ants/v2"
)

const (
	// Number of contractAddress->bool associations to keep.
	contractCacheSize = 10000
)

var (
	executorOnce sync.Once
	executor     Executor
)

type Executor struct {
	chainContext ChainContext
	chainConfig  *params.ChainConfig
	vmCfg        vm.Config
	signer       types.Signer

	workerPool    *ants.PoolWithFunc
	contractCache *lru.Cache
}

type TaskArgs struct {
	ctx          *ParallelContext
	idx          int
	intrinsicGas uint64
}

func NewExecutor(chainConfig *params.ChainConfig, chainContext ChainContext, vmCfg vm.Config) {
	executorOnce.Do(func() {
		log.Info("Init parallel executor ...")
		executor = Executor{}
		//executor.workerPool, _ = ants.NewPoolWithFunc(runtime.NumCPU(), func(i interface{}) {
		//	args := i.(TaskArgs)
		//	ctx := args.ctx
		//	idx := args.idx
		//	intrinsicGas := args.intrinsicGas
		//	executor.executeParallelTx(ctx, idx, intrinsicGas)
		//	ctx.wg.Done()
		//})
		executor.chainConfig = chainConfig
		executor.chainContext = chainContext
		executor.signer = types.NewEIP155Signer(chainConfig.ChainID)
		executor.vmCfg = vmCfg
		csc, _ := lru.New(contractCacheSize)
		executor.contractCache = csc
	})
}

func GetExecutor() *Executor {
	return &executor
}

func (exe *Executor) Signer() types.Signer {
	return exe.signer
}

func (exe *Executor) ExecuteTransactions(ctx *ParallelContext) error {
	if len(ctx.txList) > 0 {
		txDag := NewTxDag(exe.signer)
		start := time.Now()
		if err := txDag.MakeDagGraph(ctx.header.Number.Uint64(), ctx.GetState(), ctx.txList, exe); err != nil {
			return err
		}
		log.Trace("Make dag graph cost", "number", ctx.header.Number.Uint64(), "time", time.Since(start))

		start = time.Now()
		batchNo := 0
		//cTrieGet, cBuild = 0, 0
		//for !ctx.IsTimeout() && txDag.HasNext() {
		for txDag.HasNext() {
			parallelTxIdxs := txDag.Next()

			log.Trace("get parallel txs from dag", "#ids", len(parallelTxIdxs))

			if len(parallelTxIdxs) <= 0 {
				break
			}

			if len(parallelTxIdxs) == 1 && txDag.IsContract(parallelTxIdxs[0]) {
				exe.executeContractTransaction(ctx, parallelTxIdxs[0])

			} else {
				parallel.Range(0, len(parallelTxIdxs), runtime.NumCPU(), func(low, high int) {
					for _, originIdx := range parallelTxIdxs[low:high] {
						tx := ctx.GetTx(originIdx)

						intrinsicGas, err := IntrinsicGas(tx.Data(), false, false)
						if err != nil {
							ctx.buildTransferFailedResult(originIdx, err, false)
							continue
						}
						tx.SetIntrinsicGas(intrinsicGas)
						if err := ctx.gp.SubGas(intrinsicGas); err != nil {
							ctx.buildTransferFailedResult(originIdx, err, false)
							continue
						}
						executor.executeParallelTx(ctx, originIdx, intrinsicGas)
					}
				})

				//
				//for _, originIdx := range parallelTxIdxs {
				//	tx := ctx.GetTx(originIdx)
				//
				//	intrinsicGas, err := IntrinsicGas(tx.Data(), false, false)
				//	if err != nil {
				//		ctx.buildTransferFailedResult(originIdx, err, false)
				//		continue
				//	}
				//	tx.SetIntrinsicGas(intrinsicGas)
				//	if err := ctx.gp.SubGas(intrinsicGas); err != nil {
				//		ctx.buildTransferFailedResult(originIdx, err, false)
				//		continue
				//	}
				//
				//	ctx.wg.Add(1)
				//	args := TaskArgs{ctx, originIdx, intrinsicGas}
				//	_ = exe.workerPool.Invoke(args)
				//}
				//// waiting for current batch done
				//ctx.wg.Wait()

				ctx.batchMerge(batchNo, parallelTxIdxs, true)
				batchNo++
			}
		}
		// all transactions executed
		log.Trace("Execute transactions cost", "number", ctx.header.Number, "time", time.Since(start))

		//add balance for miner
		//if ctx.GetEarnings().Cmp(big.NewInt(0)) > 0 {
		//	ctx.state.AddMinerEarnings(ctx.header.Coinbase, ctx.GetEarnings())
		//}
		start = time.Now()
		ctx.state.Finalise(true)
		log.Trace("Finalise stateDB cost", "number", ctx.header.Number, "time", time.Since(start))
	}

	// dag print info
	logVerbosity := debug.GetLogVerbosity()
	if logVerbosity == log.LvlTrace {
		inf := ctx.txListInfo()
		log.Trace("TxList Info", "blockNumber", ctx.header.Number, "txList", inf)
	}
	return nil
}

//var (
//	cTrieGet time.Duration
//	cBuild   time.Duration
//)

func (exe *Executor) executeParallelTx(ctx *ParallelContext, idx int, intrinsicGas uint64) {
	//if ctx.IsTimeout() {
	//	return
	//}
	tx := ctx.GetTx(idx)

	msg, err := tx.AsMessage(exe.signer)
	if err != nil {
		//gas pool is subbed
		ctx.buildTransferFailedResult(idx, err, true)
		return
	}

	if msg.Gas() < intrinsicGas {
		ctx.buildTransferFailedResult(idx, vm.ErrOutOfGas, true)
		return
	}

	start := time.Now()
	fromObj := ctx.GetState().GetOrNewParallelStateObject(msg.From())
	//atomic.AddInt64((*int64)(&cTrieGet), int64(time.Since(start)))

	if start.Add(30 * time.Millisecond).Before(time.Now()) {
		log.Debug("Get state object overtime", "address", msg.From().String(), "duration", time.Since(start))
	}

	mgval := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasPrice())
	if fromObj.GetBalance().Cmp(mgval) < 0 {
		ctx.buildTransferFailedResult(idx, vm.ErrOutOfGas, true)
		return
	}

	minerEarnings := new(big.Int).Mul(new(big.Int).SetUint64(intrinsicGas), msg.GasPrice())
	subTotal := new(big.Int).Add(msg.Value(), minerEarnings)
	if fromObj.GetBalance().Cmp(subTotal) < 0 {
		ctx.buildTransferFailedResult(idx, vm.ErrOutOfGas, true)
		return
	}

	fromObj.SubBalance(subTotal)
	fromObj.SetNonce(fromObj.GetNonce() + 1)

	//record := time.Now()
	toObj := ctx.GetState().GetOrNewParallelStateObject(*msg.To())
	//atomic.AddInt64((*int64)(&cTrieGet), int64(time.Since(record)))

	toObj.AddBalance(msg.Value())

	//record = time.Now()
	ctx.buildTransferSuccessResult(idx, fromObj, toObj, intrinsicGas, minerEarnings)
	//atomic.AddInt64((*int64)(&cBuild), int64(time.Since(record)))

	return
}

func (exe *Executor) executeContractTransaction(ctx *ParallelContext, idx int) {
	//if ctx.IsTimeout() {
	//	return
	//}
	snap := ctx.GetState().Snapshot()
	tx := ctx.GetTx(idx)

	//log.Debug("execute contract", "txHash", tx.Hash(), "txIdx", idx, "gasPool", ctx.gp.Gas(), "txGasLimit", tx.Gas())
	ctx.GetState().Prepare(tx.Hash(), ctx.GetBlockHash(), ctx.GetState().GetTxIdx())
	receipt, err := ApplyTransaction(exe.chainConfig, exe.chainContext, nil, ctx.GetGasPool(), ctx.GetState(), ctx.GetHeader(), tx, ctx.GetBlockGasUsedHolder(), exe.vmCfg)
	if err != nil {
		log.Warn("Execute contract transaction failed", "blockNumber", ctx.GetHeader().Number.Uint64(), "txHash", tx.Hash(), "gasPool", ctx.GetGasPool().Gas(), "txGasLimit", tx.Gas(), "err", err.Error())
		ctx.GetState().RevertToSnapshot(snap)
		return
	}
	ctx.AddPackedTx(tx)
	ctx.GetState().IncreaseTxIdx()
	ctx.AddReceipt(receipt)
	log.Debug("Execute contract transaction success", "blockNumber", ctx.GetHeader().Number.Uint64(), "txHash", tx.Hash().Hex(), "gasPool", ctx.gp.Gas(), "txGasLimit", tx.Gas(), "gasUsed", receipt.GasUsed)
}

func (exe *Executor) isContract(address *common.Address, state *state.StateDB) bool {
	//if address == nil {
	//	return true
	//}
	//if cached, ok := exe.contractCache.Get(*address); ok {
	//	return cached.(bool)
	//}
	//isContract := vm.IsPrecompiledContract(*address) || state.GetCodeSize(*address) > 0
	//if isContract {
	//	exe.contractCache.Add(*address, true)
	//}
	//return isContract
	return false
}
