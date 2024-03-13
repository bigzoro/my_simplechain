package hotstuff

import (
	"github.com/bigzoro/my_simplechain/consensus"
	"github.com/bigzoro/my_simplechain/p2p"
	"github.com/bigzoro/my_simplechain/rpc"
)

const (
	// Hotstuff protocol version
	protocolVersion uint = 1

	// Maximum number of hotstuff message codes
	protocolLength uint64 = 10
)

type protocol interface {
	Handle(*p2p.Peer, p2p.MsgReadWriter, consensus.ChainReader) error

	Close() error
}

type Service struct {
	chain    consensus.ChainReader
	protocol protocol
}

func (s *Service) Protocols() []p2p.Protocol {
	return []p2p.Protocol{
		{
			Name:    "hotstuff",
			Version: protocolVersion,
			Length:  protocolLength,
			Run: func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
				return s.protocol.Handle(peer, rw, s.chain)
			},
		},
	}
}

func (s *Service) APIs() []rpc.API {
	return nil
}

func (s *Service) Start(server *p2p.Server) error {
	return nil
}

func (s *Service) Stop() error {
	return s.protocol.Close()
}
