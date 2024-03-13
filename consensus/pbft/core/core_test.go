// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"crypto/ecdsa"
	"github.com/simplechain-org/go-simplechain/crypto"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/consensus/pbft"
	"github.com/simplechain-org/go-simplechain/core/types"
	elog "github.com/simplechain-org/go-simplechain/log"
)

func makeBlock(number int64, txs ...*types.Transaction) *types.Block {
	header := &types.Header{
		Difficulty: big.NewInt(0),
		Number:     big.NewInt(number),
		GasLimit:   0,
		GasUsed:    0,
		Time:       0,
	}
	return types.NewBlock(header, txs, nil, nil)
}

func newTestProposal() pbft.Proposal {
	return makeBlock(1)
}

func newTestConclusion() pbft.Conclusion {
	return makeBlock(1)
}

func newTestLightProposal(txs ...*types.Transaction) pbft.LightProposal {
	return types.NewLightBlock(makeBlock(1, txs...))
}

func newTransactions(n int, signer types.Signer, key *ecdsa.PrivateKey) types.Transactions {
	var txs types.Transactions

	for i := 0; i < n; i++ {
		tx := types.NewTransaction(uint64(i), common.Address{}, common.Big1, 21000, common.Big1, make([]byte, 64))

		signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
		if err != nil {
			continue
		}
		signed, err := tx.WithSignature(signer, signature)
		if err != nil {
			continue
		}
		txs = append(txs, signed)
	}

	return txs
}

func TestNewRequest(t *testing.T) {
	testLogger.SetHandler(elog.StdoutHandler)

	N := uint64(4)
	F := uint64(1)

	sys := NewTestSystemWithBackend(N, F)

	close := sys.Run(true)
	defer close()

	request1 := makeBlock(1)
	sys.backends[0].NewRequest(request1)

	<-time.After(1 * time.Second)

	request2 := makeBlock(2)
	sys.backends[0].NewRequest(request2)

	<-time.After(1 * time.Second)

	for _, backend := range sys.backends {
		if len(backend.committedMsgs) != 2 {
			t.Errorf("the number of executed requests mismatch: have %v, want 2", len(backend.committedMsgs))
		}
		if !reflect.DeepEqual(request1.Number(), backend.committedMsgs[0].commitProposal.Number()) {
			t.Errorf("the number of requests mismatch: have %v, want %v", request1.Number(), backend.committedMsgs[0].commitProposal.Number())
		}
		if !reflect.DeepEqual(request2.Number(), backend.committedMsgs[1].commitProposal.Number()) {
			t.Errorf("the number of requests mismatch: have %v, want %v", request2.Number(), backend.committedMsgs[1].commitProposal.Number())
		}
	}
}

func TestQuorumSize(t *testing.T) {
	N := uint64(4)
	F := uint64(1)

	sys := NewTestSystemWithBackend(N, F)
	backend := sys.backends[0]
	c := backend.engine.(*core)

	valSet := c.valSet
	for i := 1; i <= 1000; i++ {
		valSet.AddValidator(common.BytesToAddress([]byte(string(rune(i)))))
		if 2*c.Confirmations() <= (valSet.Size()+valSet.F()) || 2*c.Confirmations() > (valSet.Size()+valSet.F()+2) {
			t.Errorf("quorumSize constraint failed, expected value (2*Confirmations > Size+F && 2*Confirmations <= Size+F+2) to be:%v, got: %v, for size: %v", true, false, valSet.Size())
		}
	}
}
