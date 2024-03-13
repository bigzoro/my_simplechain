package eth

import (
	"github.com/bigzoro/my_simplechain/common"
	mapset "github.com/deckarep/golang-set"
)

type SuperManager struct {
	addresses mapset.Set
}

func NewSuperManager() *SuperManager {
	return &SuperManager{
		addresses: mapset.NewSet(),
	}
}
func (s *SuperManager) AddManager(addr common.Address) {
	if !s.addresses.Contains(addr) {
		s.addresses.Add(addr)
	}
}
func (s *SuperManager) IsManager(addr common.Address) bool {
	return s.addresses.Contains(addr)
}
