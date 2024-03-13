package backend

import (
	"github.com/simplechain-org/go-simplechain/consensus/raft"
)

type RaftNodeInfo struct {
	ClusterSize    int             `json:"clusterSize"`
	Role           string          `json:"role"`
	Address        *raft.Address   `json:"address"`
	PeerAddresses  []*raft.Address `json:"peerAddresses"`
	RemovedPeerIds []uint16        `json:"removedPeerIds"`
	AppliedIndex   uint64          `json:"appliedIndex"`
	SnapshotIndex  uint64          `json:"snapshotIndex"`
}

type PublicRaftAPI struct {
	raftService *RaftService
}

func NewPublicRaftAPI(raftService *RaftService) *PublicRaftAPI {
	return &PublicRaftAPI{raftService}
}

func (s *PublicRaftAPI) Role() string {
	return s.raftService.RaftProtocolManager.NodeInfo().Role
}

//func (s *PublicRaftAPI) AddPeer(enodeId string) (uint16, error) {
//	return s.raftService.RaftProtocolManager.ProposeNewPeer(enodeId)
//}
//
//func (s *PublicRaftAPI) RemovePeer(raftId uint16) {
//	s.raftService.RaftProtocolManager.ProposePeerRemoval(raftId)
//}

func (s *PublicRaftAPI) Leader() (string, error) {

	addr, err := s.raftService.RaftProtocolManager.LeaderAddress()
	if nil != err {
		return "", err
	}
	return addr.NodeId.String(), nil
}

func (s *PublicRaftAPI) Cluster() []*raft.Address {
	nodeInfo := s.raftService.RaftProtocolManager.NodeInfo()
	return append(nodeInfo.PeerAddresses, nodeInfo.Address)
}

func (s *PublicRaftAPI) GetRaftId(enodeId string) (uint16, error) {
	return s.raftService.RaftProtocolManager.FetchRaftId(enodeId)
}

func (s *PublicRaftAPI) GetMaxRaftId() uint16 {
	return s.raftService.RaftProtocolManager.MaxRaftId() + 1
}
