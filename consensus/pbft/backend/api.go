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

package backend

import (
	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/consensus"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/rpc"
)

// API is a user facing RPC API to dump Istanbul state
type API struct {
	chain consensus.ChainReader
	pbft  *backend
}

// BlockSigners is contains who created and who signed a particular block, denoted by its number and hash
type BlockSigners struct {
	Number     uint64
	Hash       common.Hash
	Author     common.Address
	Committers []common.Address
}

// NodeAddress returns the public address that is used to sign block headers in IBFT
func (api *API) NodeAddress() common.Address {
	return api.pbft.Address()
}

// GetSignersFromBlock returns the signers and minter for a given block number, or the
// latest block available if none is specified
func (api *API) GetSignersFromBlock(number *rpc.BlockNumber) (*BlockSigners, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}

	if header == nil {
		return nil, errUnknownBlock
	}

	return api.signers(header)
}

// GetSignersFromBlockByHash returns the signers and minter for a given block hash
func (api *API) GetSignersFromBlockByHash(hash common.Hash) (*BlockSigners, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}

	return api.signers(header)
}

func (api *API) signers(header *types.Header) (*BlockSigners, error) {
	author, err := api.pbft.Author(header)
	if err != nil {
		return nil, err
	}

	committers, err := api.pbft.Signers(header)
	if err != nil {
		return nil, err
	}

	return &BlockSigners{
		Number:     header.Number.Uint64(),
		Hash:       header.Hash(),
		Author:     author,
		Committers: committers,
	}, nil
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.pbft.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.pbft.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetValidators retrieves the list of authorized validators at the specified block.
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the validators from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pbft.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.validators(), nil
}

// GetValidatorsAtHash retrieves the state snapshot at a given block.
func (api *API) GetValidatorsAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pbft.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.validators(), nil
}

// Candidates returns the current candidates the node tries to uphold and vote on.
func (api *API) Candidates() map[common.Address]bool {
	api.pbft.candidatesLock.RLock()
	defer api.pbft.candidatesLock.RUnlock()

	proposals := make(map[common.Address]bool)
	for address, auth := range api.pbft.candidates {
		proposals[address] = auth
	}
	return proposals
}

// Propose injects a new authorization candidate that the validator will attempt to
// push through.
func (api *API) Propose(address common.Address, auth bool) {
	api.pbft.candidatesLock.Lock()
	defer api.pbft.candidatesLock.Unlock()

	api.pbft.candidates[address] = auth
}

// Discard drops a currently running candidate, stopping the validator from casting
// further votes (either for or against).
func (api *API) Discard(address common.Address) {
	api.pbft.candidatesLock.Lock()
	defer api.pbft.candidatesLock.Unlock()

	delete(api.pbft.candidates, address)
}
