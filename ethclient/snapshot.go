package ethclient

import (
	"context"
	"github.com/bigzoro/my_simplechain/common"
	"math/big"

	"github.com/bigzoro/my_simplechain"
	"github.com/bigzoro/my_simplechain/consensus/clique"
)

func (ec *Client) GetSnapshot(ctx context.Context, number *big.Int) (*clique.Snapshot, error) {
	var r *clique.Snapshot
	err := ec.c.CallContext(ctx, &r, "clique_getSnapshot", toBlockNumArg(number))
	if err == nil {
		if r == nil {
			return nil, simplechain.NotFound
		}
	}
	return r, err
}

// Propose auth 表示的是授权和去授权的意思
// true 表示授权
// false 表示的是把权力收回
func (ec *Client) Propose(ctx context.Context, address common.Address, auth bool) error {
	var result interface{}
	err := ec.c.CallContext(ctx, &result, "clique_propose", address, auth)
	if err != nil {
		return err
	}
	return nil
}

func (ec *Client) GetSigners(ctx context.Context, number *big.Int) ([]common.Address, error) {
	var result []common.Address
	err := ec.c.CallContext(ctx, &result, "clique_getSigners", toBlockNumArg(number))
	if err != nil {
		return nil, err
	}
	return result, nil
}
