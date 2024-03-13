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
	"sync"
	"time"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/log"
	"github.com/simplechain-org/go-simplechain/rlp"
)

func (s *StateDB) Merge(idx int, from, to *ParallelStateObject, deleteEmptyObjects bool) {
	if from.stateObject.address != to.stateObject.address {
		if from.stateObject.suicided || (deleteEmptyObjects && from.stateObject.empty()) {
			log.Warn("deleteStateObject", "from", from.stateObject.address.String(), "suicided", from.stateObject.suicided, "empty", from.stateObject.empty())
			s.deleteStateObject(from.stateObject)
		} else {
			s.stateObjects[from.stateObject.address] = from.stateObject
			s.journal.append(balanceChange{
				account: &from.stateObject.address,
				prev:    from.prevAmount,
			})
			s.stateObjectsDirty[from.stateObject.address] = struct{}{}
		}
	}
	if to.stateObject.suicided || (deleteEmptyObjects && to.stateObject.empty()) {
		log.Warn("deleteStateObject", "to", to.stateObject.address.String(), "suicided", to.stateObject.suicided, "empty", to.stateObject.empty())
		s.deleteStateObject(to.stateObject)
	} else {
		if to.createFlag {
			s.journal.append(createObjectChange{account: &to.stateObject.address})
		}
		s.stateObjects[to.stateObject.address] = to.stateObject
		s.journal.append(balanceChange{
			account: &to.stateObject.address,
			prev:    to.prevAmount,
		})
		s.stateObjectsDirty[to.stateObject.address] = struct{}{}
	}
}

func (s *StateDB) AddMinerEarnings(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		//stateObject.db = s
		stateObject.AddBalance(amount)
	}
}

var (
	parallelLocker sync.Mutex
)

func (s *StateDB) GetOrNewParallelStateObject(addr common.Address) *ParallelStateObject {
	stateObject := s.justGetStateObject(addr)
	if stateObject == nil || stateObject.deleted {
		log.Debug("Cannot find stateObject in Parallel", "addr", addr.String(), "isNil", stateObject == nil)
		return s.justCreateObject(addr)
	}
	return NewParallelStateObject(stateObject, false)
}

func (s *StateDB) justGetStateObject(addr common.Address) (stateObject *stateObject) {
	if obj := s.justGetStateObjectCache(addr); obj != nil {
		if obj.deleted {
			return nil
		}
		return obj
	}
	// Load the object from the database.
	start := time.Now()
	parallelLocker.Lock()
	if start.Add(20 * time.Millisecond).Before(time.Now()) {
		log.Trace("Get parallelLocker overtime", "address", addr.String(), "duration", time.Since(start))
	}
	start = time.Now()
	enc, err := s.trie.TryGet(addr[:])
	if start.Add(20 * time.Millisecond).Before(time.Now()) {
		log.Trace("Trie tryGet overtime", "address", addr.String(), "duration", time.Since(start))
	}
	parallelLocker.Unlock()
	if len(enc) == 0 {
		s.setError(err)
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		log.Error("Failed to decode state object", "addr", addr, "err", err)
		return nil
	}
	obj := newObject(s, addr, data)
	//do not set to state.stateObjects.
	//self.setStateObject(obj)
	return obj
}

func (s *StateDB) justGetStateObjectCache(addr common.Address) (stateObject *stateObject) {
	// Prefer 'live' objects.
	if obj := s.stateObjects[addr]; obj != nil {
		return obj
	}

	//TODO(yc) chained bft statedb
	//self.refLock.Lock()
	//parentDB := self.parent
	//parentCommitted := self.parentCommitted
	//refLock := &self.refLock
	//
	//for parentDB != nil {
	//	obj := parentDB.getStateObjectLocalCache(addr)
	//	if obj != nil {
	//		refLock.Unlock()
	//		cpy := obj.copy(self)
	//		//do not set to state.stateObjects.
	//		//self.setStateObject(cpy)
	//		return cpy
	//	} else if parentCommitted {
	//		refLock.Unlock()
	//		return nil
	//	}
	//
	//	if obj == nil {
	//		refLock.Unlock()
	//		parentDB.refLock.Lock()
	//		refLock = &parentDB.refLock
	//		if parentDB.parent == nil {
	//			break
	//		}
	//		parentCommitted = parentDB.parentCommitted
	//		parentDB = parentDB.parent
	//	}
	//}
	//
	//refLock.Unlock()
	return nil
}

func (s *StateDB) justCreateObject(addr common.Address) *ParallelStateObject {
	//newobj := newObject(self, addr, Account{})
	newobj := newObject(s, addr, Account{})
	//self.journal.append(createObjectChange{account: &addr})
	newobj.setNonce(0)
	return &ParallelStateObject{
		stateObject: newobj,
		prevAmount:  big.NewInt(0),
		createFlag:  true,
	}
	//return self.createObject(addr)
}
