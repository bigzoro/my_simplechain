package permission

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bigzoro/my_simplechain/accounts/abi/bind"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/log"
)

var (
	permissionKey = []byte("0x2022040600000000000000000000000000000002020021001")
	storeAbiKey   = []byte("0x2022040600000000000000000000000000000002020021002")
)

type QuorumControlsAPI struct {
	permissionService *Service
}

// AddPeer 添加节点
func (q *QuorumControlsAPI) AddPeer(url string, from common.Address) (bool, error) {
	return q.permissionService.AddPeer(url, from)
}

// RemovePeer 移除节点
func (q *QuorumControlsAPI) RemovePeer(url string) (bool, error) {
	return q.permissionService.RemovePeer(url)
}

// SetAdminNode 设置给定的节点成为管理节点
// 在联盟网络初始化完成之前进行
func (q *QuorumControlsAPI) SetAdminNode(fullNodeId, nodeName string, address common.Address, from common.Address) (string, error) {
	return q.permissionService.SetAdminNode(fullNodeId, nodeName, address, from)
}

// InitFinish 完成联盟网络初始化
func (q *QuorumControlsAPI) InitFinish(from common.Address) (string, error) {
	return q.permissionService.InitFinish(from)
}

// MakeProposalForJoin 发起加入联盟提案
func (q *QuorumControlsAPI) MakeProposalForJoin(fullNodeId string, nodeName string, nodeAddress common.Address, from common.Address) (string, error) {
	return q.permissionService.MakeProposalForJoin(fullNodeId, nodeName, nodeAddress, from)
}

// AcceptProposalForJoin 接受加入联盟提案
func (q *QuorumControlsAPI) AcceptProposalForJoin(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.AcceptProposalForJoin(fullNodeId, from)
}

// RejectProposalForJoin 拒绝加入联盟提案
func (q *QuorumControlsAPI) RejectProposalForJoin(fullNodeId string, from common.Address) (string, error) {
	// 0 加入联盟
	opCode := 0
	return q.permissionService.Disagree(fullNodeId, opCode, from)
}

// MakeProposalForAdmin 发起成为管理节点提案
func (q *QuorumControlsAPI) MakeProposalForAdmin(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.MakeProposalForAdmin(fullNodeId, from)
}

// AcceptProposalForAdmin 接受成为管理节点提案
func (q *QuorumControlsAPI) AcceptProposalForAdmin(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.AcceptProposalForAdmin(fullNodeId, from)
}

// RejectProposalForAdmin 拒绝成为管理节点提案
func (q *QuorumControlsAPI) RejectProposalForAdmin(fullNodeId string, from common.Address) (string, error) {
	//2 升级为管理节点
	opCode := 2
	return q.permissionService.Disagree(fullNodeId, opCode, from)
}

// MakeProposalForCommon 发起成为普通节点提案
func (q *QuorumControlsAPI) MakeProposalForCommon(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.MakeProposalForCommon(fullNodeId, from)
}

// AcceptProposalForCommon 接受成为普通节点提案
func (q *QuorumControlsAPI) AcceptProposalForCommon(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.AcceptProposalForCommon(fullNodeId, from)
}

// RejectProposalForCommon 拒绝成为普通节点提案
func (q *QuorumControlsAPI) RejectProposalForCommon(fullNodeId string, from common.Address) (string, error) {
	// 3 降级成普通节点
	opCode := 3
	return q.permissionService.Disagree(fullNodeId, opCode, from)
}

// MakeProposalForExit 发起节点退出联盟提案
func (q *QuorumControlsAPI) MakeProposalForExit(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.MakeProposalForExit(fullNodeId, from)
}

// AcceptProposalForExit 接受节点退出联盟提案
func (q *QuorumControlsAPI) AcceptProposalForExit(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.AcceptProposalForExit(fullNodeId, from)
}

// RejectProposalForExit 拒绝节点退出联盟提案
func (q *QuorumControlsAPI) RejectProposalForExit(fullNodeId string, from common.Address) (string, error) {
	// 1 退出联盟
	opCode := 1
	return q.permissionService.Disagree(fullNodeId, opCode, from)
}

// IsNetworkInitFinished 联盟初始化网络是否完成
func (q *QuorumControlsAPI) IsNetworkInitFinished() (bool, error) {
	return q.permissionService.isInitFinished(), nil
}

// UpdateNodeInfo 节点自己更新ip和端口
func (q *QuorumControlsAPI) UpdateNodeInfo(from common.Address, ip string, port string) (string, error) {
	return q.permissionService.UpdateNodeInfo(from, ip, port)
}

// Exit 自己直接退出网络
func (q *QuorumControlsAPI) Exit(from common.Address) (string, error) {
	return q.permissionService.Exit(from)
}

// GetNodeByRole 根据角色获取节点
// check pass
func (q *QuorumControlsAPI) GetNodeByRole(role *big.Int, from common.Address) (string, error) {
	return q.permissionService.GetNodeByRole(role, from)
}

// GetNodeRole 获取节点的角色
func (q *QuorumControlsAPI) GetNodeRole(fullNodeId string, from common.Address) (*big.Int, error) {
	return q.permissionService.GetNodeRole(fullNodeId, from)
}

// GetNodeInfoByName 根据节点名称获取节点信息
func (q *QuorumControlsAPI) GetNodeInfoByName(nodeName string, from common.Address) (string, error) {
	return q.permissionService.GetNodeInfoByName(nodeName, from)
}

// GetStateMap 获取节点申请的统计信息
func (q *QuorumControlsAPI) GetStateMap(fullNodeId string, opCode string, from common.Address) (string, error) {
	return q.permissionService.GetStateMap(fullNodeId, opCode, from)
}

// GetNodeInfo 获取节点信息
// check pass
func (q *QuorumControlsAPI) GetNodeInfo(fullNodeId string, from common.Address) (string, error) {
	return q.permissionService.GetNodeInfo(fullNodeId, from)
}

// GetAllStatingRecord 获取正在进行的统计记录
func (q *QuorumControlsAPI) GetAllStatingRecord(from common.Address) (string, error) {
	return q.permissionService.GetAllStatingRecord(from)
}

// IsAdmin 是否是管理节点
// check pass
func (q *QuorumControlsAPI) IsAdmin(fullNodeId string, from common.Address) (bool, error) {
	return q.permissionService.IsAdmin(fullNodeId, from)
}

// SetPermissionContractAddress 设置权限合约地址
// check pass
func (q *QuorumControlsAPI) SetPermissionContractAddress(addr common.Address) (bool, error) {
	return q.permissionService.SetContractAddress(addr)
}

// GetPermissionContractAddress 获取权限合约地址
// check pass
func (q *QuorumControlsAPI) GetPermissionContractAddress() (string, error) {
	var permission string
	//read from leveldb
	addr, err := loadContractAddress(permissionKey, q.permissionService.GetCommonDb())
	if err != nil {
		log.Warn("permission service warning, can not get permission address from db.", "err", err, "if addr is nil", addr == (common.Address{}))
		return permission, err
	}
	if addr == (common.Address{}) {
		return permission, nil
	}
	permission = addr.String()
	return permission, nil
}

// SetStoreContractAddress 设置存储合约的地址
// check pass
func (q *QuorumControlsAPI) SetStoreContractAddress(addr common.Address) (bool, error) {
	q.permissionService.storeAbiAddr = addr
	storeAbiContract, err := NewStoreAbi(addr, q.permissionService.ethClient)
	if err != nil {
		return false, err
	}
	q.permissionService.storeAbiContract = storeAbiContract
	//store address to db
	err = storeContractAddress(storeAbiKey, addr, q.permissionService.GetCommonDb())
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetStoreContractAddress 获取存储abi合约地址
// check pass
func (q *QuorumControlsAPI) GetStoreContractAddress() (string, error) {
	var storeAbi string
	addr, err := loadContractAddress(storeAbiKey, q.permissionService.GetCommonDb())
	if err != nil {
		log.Warn("permission service warning, can not get storeAbi address from db.", "err", err, "if addr is nil", addr == (common.Address{}))
		return storeAbi, err
	}
	if addr == (common.Address{}) {
		return storeAbi, errors.New("please set store contract address first")
	}
	storeAbi = addr.String()
	return storeAbi, nil
}

// StoreContractAbi 保存合约的abi
func (q *QuorumControlsAPI) StoreContractAbi(contractAddress common.Address, contractName string, abi string, from common.Address) (string, error) {
	result := ""
	if q.permissionService.storeAbiContract == nil {
		addr, err := loadContractAddress(storeAbiKey, q.permissionService.GetCommonDb())
		if err != nil {
			return result, err
		}
		if addr == (common.Address{}) {
			return result, errors.New("please set store contract address")
		}
		storeAbiContract, err := NewStoreAbi(addr, q.permissionService.ethClient)
		if err != nil {
			return result, err
		}
		q.permissionService.storeAbiContract = storeAbiContract
	}
	auth, err := q.permissionService.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := q.permissionService.storeAbiContract.Set(auth, contractName, contractAddress, abi)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, nil
}

// GetContractAbi 根据合约名称获取合约的abi
func (q *QuorumControlsAPI) GetContractAbi(contractName string, from common.Address) (string, error) {
	result := ""
	if q.permissionService.storeAbiContract == nil {
		addr, err := loadContractAddress(storeAbiKey, q.permissionService.GetCommonDb())
		storeAbiContract, err := NewStoreAbi(addr, q.permissionService.ethClient)
		if err != nil {
			return result, err
		}
		q.permissionService.storeAbiContract = storeAbiContract
	}
	opts := &bind.CallOpts{From: from}
	addr, abi, err := q.permissionService.storeAbiContract.GetAbi(opts, contractName)
	if err != nil {
		return result, err
	}
	return fmt.Sprintf("%v@%v", addr.String(), abi), nil
}

func (q *QuorumControlsAPI) UpdateNodeName(fullNodeId string, nodeName string, from common.Address) (string, error) {
	return q.permissionService.UpdateNodeName(fullNodeId, nodeName, from)
}

func (q *QuorumControlsAPI) GetAdminCount() (*big.Int, error) {
	return q.permissionService.GetAdminCount()
}

// NodeExists 节点是否存在
func (q *QuorumControlsAPI) NodeExists(fullNodeId string) (bool, error) {
	return q.permissionService.nodeExists(fullNodeId), nil
}
