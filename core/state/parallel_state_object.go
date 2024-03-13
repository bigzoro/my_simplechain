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

package state

import (
	"math/big"
)

type ParallelStateObject struct {
	stateObject *stateObject
	prevAmount  *big.Int
	createFlag  bool
}

func NewParallelStateObject(stateObject *stateObject, createFlag bool) *ParallelStateObject {
	return &ParallelStateObject{
		stateObject: stateObject,
		prevAmount:  new(big.Int).Set(stateObject.Balance()),
		createFlag:  createFlag,
	}
}

func (parallelObject *ParallelStateObject) GetNonce() uint64 {
	return parallelObject.stateObject.Nonce()
}

func (parallelObject *ParallelStateObject) SetNonce(nonce uint64) {
	parallelObject.stateObject.setNonce(nonce)
}

func (parallelObject *ParallelStateObject) GetBalance() *big.Int {
	return parallelObject.stateObject.Balance()
}

func (parallelObject *ParallelStateObject) AddBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	parallelObject.stateObject.setBalance(new(big.Int).Add(parallelObject.stateObject.Balance(), amount))
}

func (parallelObject *ParallelStateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	parallelObject.stateObject.setBalance(new(big.Int).Sub(parallelObject.stateObject.Balance(), amount))
}

func (parallelObject *ParallelStateObject) UpdateRoot() {
	parallelObject.stateObject.updateRoot(parallelObject.stateObject.db.db)
}
