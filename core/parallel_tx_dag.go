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
	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/core/dag"
	"github.com/simplechain-org/go-simplechain/core/state"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/internal/debug"
	"github.com/simplechain-org/go-simplechain/log"
)

type TxDag struct {
	dag       *dag.Dag
	signer    types.Signer
	contracts map[int]struct{}
}

func NewTxDag(signer types.Signer) *TxDag {
	txDag := &TxDag{
		signer:    signer,
		contracts: make(map[int]struct{}),
	}
	return txDag
}

func (txDag *TxDag) MakeDagGraph(blockNumber uint64, state *state.StateDB, txs []*types.Transaction, exe *Executor) error {
	txDag.dag = dag.NewDag(len(txs))
	//save all transfer addresses between two contracts(precompiled and user defined)
	transferAddressMap := make(map[common.Address]int, 0)
	latestPrecompiledIndex := -1
	for index, tx := range txs {
		if tx.From(txDag.signer) == (common.Address{}) {
			log.Error("The from of the transaction cannot be resolved", "number", blockNumber, "index", index)
			continue
		}

		if exe.isContract(tx.To(), state) {
			txDag.contracts[index] = struct{}{}
			if index > 0 {
				if index-latestPrecompiledIndex > 1 {
					for begin := latestPrecompiledIndex + 1; begin < index; begin++ {
						txDag.dag.AddEdge(begin, index)
					}
				} else if index-latestPrecompiledIndex == 1 {
					txDag.dag.AddEdge(latestPrecompiledIndex, index)
				}
			}
			latestPrecompiledIndex = index
			//reset transferAddressMap
			if len(transferAddressMap) > 0 {
				transferAddressMap = make(map[common.Address]int, 0)
			}
		} else {
			dependFound := 0

			if dependIdx, ok := transferAddressMap[tx.From(txDag.signer)]; ok {
				txDag.dag.AddEdge(dependIdx, index)
				dependFound++
			}

			if dependIdx, ok := transferAddressMap[*tx.To()]; ok {
				txDag.dag.AddEdge(dependIdx, index)
				dependFound++
			}
			if dependFound == 0 && latestPrecompiledIndex >= 0 {
				txDag.dag.AddEdge(latestPrecompiledIndex, index)
			}

			transferAddressMap[tx.From(txDag.signer)] = index
			transferAddressMap[*tx.To()] = index
		}
	}
	// dag print info
	logVerbosity := debug.GetLogVerbosity()
	if logVerbosity == log.LvlTrace {
		buff, err := txDag.dag.Print()
		if err != nil {
			log.Error("print DAG Graph error!", "blockNumber", blockNumber, "err", err)
			return nil
		}
		log.Trace("DAG Graph", "blockNumber", blockNumber, "info", buff.String())
	}

	return nil
}

func (txDag *TxDag) HasNext() bool {
	return txDag.dag.HasNext()
}

func (txDag *TxDag) Next() []int {
	return txDag.dag.Next()
}

func (txDag *TxDag) IsContract(idx int) bool {
	if _, ok := txDag.contracts[idx]; ok {
		return true
	}
	return false
}
