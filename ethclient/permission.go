package ethclient

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/simplechain-org/go-simplechain/common"
)

// AddPeer 添加节点
func (ec *Client) AddPeer(ctx context.Context, url string, from common.Address) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_addPeer", url, from)
	return result, err
}

// RemovePeer 移除节点
func (ec *Client) RemovePeer(ctx context.Context, url string) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_removePeer", url)
	return result, err
}

// SetAdminNode 设置给定的节点成为管理节点
// 在联盟网络初始化完成之前进行
func (ec *Client) SetAdminNode(ctx context.Context, fullNodeId string, nodeName string, address common.Address, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_setAdminNode", fullNodeId, nodeName, address, from)
	return result, err
}

// InitFinish 完成联盟网络初始化
func (ec *Client) InitFinish(ctx context.Context, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_initFinish", from)
	return result, err
}

// MakeProposalForJoin 发起加入联盟提案
func (ec *Client) MakeProposalForJoin(ctx context.Context, fullNodeId string, nodeName string, nodeAddress common.Address, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_makeProposalForJoin", fullNodeId, nodeName, nodeAddress, from)
	return result, err
}

// AcceptProposalForJoin 接受加入联盟提案
func (ec *Client) AcceptProposalForJoin(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_acceptProposalForJoin", fullNodeId, from)
	return result, err
}

// RejectProposalForJoin 拒绝加入联盟提案
func (ec *Client) RejectProposalForJoin(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_rejectProposalForJoin", fullNodeId, from)
	return result, err
}

// MakeProposalForAdmin 发起成为管理节点提案
func (ec *Client) MakeProposalForAdmin(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_makeProposalForAdmin", fullNodeId, from)
	return result, err
}

// AcceptProposalForAdmin 接受成为管理节点提案
func (ec *Client) AcceptProposalForAdmin(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_acceptProposalForAdmin", fullNodeId, from)
	return result, err
}

// RejectProposalForAdmin 拒绝成为管理节点提案
func (ec *Client) RejectProposalForAdmin(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_rejectProposalForAdmin", fullNodeId, from)
	return result, err
}

// MakeProposalForCommon 发起成为普通节点提案
func (ec *Client) MakeProposalForCommon(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_makeProposalForCommon", fullNodeId, from)
	return result, err
}

//AcceptProposalForCommon 接受成为普通节点提案
func (ec *Client) AcceptProposalForCommon(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_acceptProposalForCommon", fullNodeId, from)
	return result, err
}

// RejectProposalForCommon 拒绝成为普通节点提案
func (ec *Client) RejectProposalForCommon(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_rejectProposalForCommon", fullNodeId, from)
	return result, err
}

// MakeProposalForExit 发起节点退出联盟提案
func (ec *Client) MakeProposalForExit(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_makeProposalForExit", fullNodeId, from)
	return result, err
}

// AcceptProposalForExit 接受节点退出联盟提案
func (ec *Client) AcceptProposalForExit(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_acceptProposalForExit", fullNodeId, from)
	return result, err
}

// RejectProposalForExit 拒绝节点退出联盟提案
func (ec *Client) RejectProposalForExit(ctx context.Context, fullNodeId string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_rejectProposalForExit", fullNodeId, from)
	return result, err
}

// IsNetworkInitFinished 联盟初始化网络是否完成
func (ec *Client) IsNetworkInitFinished(ctx context.Context) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_isNetworkInitFinished")
	return result, err
}

// UpdateNodeInfo 节点自己更新ip和端口
func (ec *Client) UpdateNodeInfo(ctx context.Context, from common.Address, ip string, port string) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_updateNodeInfo", from, ip, port)
	return result, err
}

// Exit 自己直接退出网络
func (ec *Client) Exit(ctx context.Context, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_exit", from)
	return result, err
}

// GetNodeByRole 根据角色获取节点
// check pass
func (ec *Client) GetNodeByRole(ctx context.Context, role *big.Int, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getNodeByRole", role, from)
	return result, err
}

// GetNodeRole 获取节点的角色
func (ec *Client) GetNodeRole(ctx context.Context, fullNodeId string, from common.Address) (*big.Int, error) {
	var result big.Int
	err := ec.c.CallContext(ctx, &result, "permission_getNodeRole", fullNodeId, from)
	return &result, err
}

// GetNodeInfoByName 根据节点名称获取节点信息
func (ec *Client) GetNodeInfoByName(ctx context.Context, nodeName string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getNodeInfoByName", nodeName, from)
	return result, err
}

// GetAllStatingRecord 获取正在进行的统计记录
func (ec *Client) GetAllStatingRecord(ctx context.Context, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getAllStatingRecord", from)
	return result, err
}

// IsAdmin 是否是管理节点
// check pass
func (ec *Client) IsAdmin(ctx context.Context, fullNodeId string, from common.Address) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_isAdmin", fullNodeId, from)
	return result, err
}

// SetPermissionContractAddress 设置权限合约地址
// check pass
func (ec *Client) SetPermissionContractAddress(ctx context.Context, addr common.Address) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_setPermissionContractAddress", addr)
	return result, err
}

// GetPermissionContractAddress 获取权限合约地址
// check pass
func (ec *Client) GetPermissionContractAddress(ctx context.Context) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getPermissionContractAddress")
	return result, err
}

// SetStoreContractAddress 设置存储合约的地址
// check pass
func (ec *Client) SetStoreContractAddress(ctx context.Context, addr common.Address) (bool, error) {
	var result bool
	err := ec.c.CallContext(ctx, &result, "permission_setStoreContractAddress", addr)
	return result, err
}

// GetStoreContractAddress 获取存储abi合约地址
// check pass
func (ec *Client) GetStoreContractAddress(ctx context.Context) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getStoreContractAddress")
	return result, err
}

// StoreContractAbi 保存合约的abi
func (ec *Client) StoreContractAbi(ctx context.Context, contractAddress common.Address, contractName string, abi string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_storeContractAbi", contractAddress, contractName, abi, from)
	return result, err
}

// GetContractAbi 根据合约名称获取合约的abi
func (ec *Client) GetContractAbi(ctx context.Context, contractName string, from common.Address) (string, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getContractAbi", contractName, from)
	return result, err
}

func (ec *Client) GetAdminCount(ctx context.Context) (int, error) {
	var result big.Int
	err := ec.c.CallContext(ctx, &result, "permission_getAdminCount")
	return int(result.Int64()), err
}

type NodeInfo struct {
	NodeId       string
	Ip           string
	Port         string
	NodeName     string
	NodeAddress  string
	Role         string
	IsOriginator bool
	CreatedAt    int64
}

// GetNodeInfo 获取节点信息
// check pass
func (ec *Client) GetNodeInfo(ctx context.Context, fullNodeId string, from common.Address) (*NodeInfo, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getNodeInfo", fullNodeId, from)
	arr := strings.Split(result, ",")
	var nodeInfo NodeInfo
	if len(arr) == 8 {
		nodeInfo.NodeId = arr[0]
		nodeInfo.Ip = arr[1]
		nodeInfo.Port = arr[2]
		nodeInfo.NodeName = arr[3]
		nodeInfo.NodeAddress = arr[4]
		nodeInfo.Role = arr[5]
		if arr[6] == "true" {
			nodeInfo.IsOriginator = true
		} else {
			nodeInfo.IsOriginator = false
		}
		createdAt, err := strconv.ParseInt(arr[7], 10, 64)
		if err == nil {
			nodeInfo.CreatedAt = createdAt
		} else {
			fmt.Println("createdAt ParseInt error", arr[7])
		}
	}
	return &nodeInfo, err
}

type VoteStats struct {
	NodeId        string //节点id
	Agree         int    //同意票
	Disagree      int    //反对票
	ProposeNodeId string //提议者
	OpCode        string //操作
	Complete      bool   //投票完成
}

const (
	JoinAction        string = "join"         //加入网络
	UpgradeAction     string = "upgrade"      //升级操作
	DemoteAction      string = "demote"       //降级操作
	NetworkExitAction string = "network_exit" //退出网络
)

//string opJoin="0";
//// 1 退出联盟
//string opExit="1";
//// 2 升级为管理节点
//string opAdmin="2";
//// 3 降级成普通节点
//string opCommon="3";

// GetStateMap 获取节点申请的统计信息
func (ec *Client) GetStateMap(ctx context.Context, fullNodeId string, opCode string, from common.Address) (*VoteStats, error) {
	var result string
	err := ec.c.CallContext(ctx, &result, "permission_getStateMap", fullNodeId, opCode, from)
	arr := strings.Split(result, ",")
	var voteStats VoteStats
	if len(arr) == 5 {
		voteStats.NodeId = fullNodeId
		agree, err := strconv.Atoi(arr[0])
		if err == nil {
			voteStats.Agree = agree
		}
		disagree, err := strconv.Atoi(arr[1])
		if err == nil {
			voteStats.Disagree = disagree
		}
		voteStats.ProposeNodeId = arr[2]
		switch arr[3] {
		case "0":
			voteStats.OpCode = JoinAction
		case "1":
			voteStats.OpCode = NetworkExitAction
		case "2":
			voteStats.OpCode = UpgradeAction
		case "3":
			voteStats.OpCode = DemoteAction
		}
		if arr[4] == "1" {
			voteStats.Complete = true
		}

	}
	return &voteStats, err
}
