package permission

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bigzoro/my_simplechain/accounts"
	"github.com/bigzoro/my_simplechain/accounts/abi/bind"
	"github.com/bigzoro/my_simplechain/accounts/keystore"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/consensus/raft/backend"
	"github.com/bigzoro/my_simplechain/crypto"
	"github.com/bigzoro/my_simplechain/eth"
	"github.com/bigzoro/my_simplechain/ethclient"
	"github.com/bigzoro/my_simplechain/ethdb"
	"github.com/bigzoro/my_simplechain/event"
	"github.com/bigzoro/my_simplechain/log"
	"github.com/bigzoro/my_simplechain/node"
	"github.com/bigzoro/my_simplechain/p2p"
	"github.com/bigzoro/my_simplechain/p2p/enode"
	"github.com/bigzoro/my_simplechain/rpc"
)

var (
	Join     = 0
	Remove   = 1
	Normal   = 0 //normal node
	Isolated = 1
	Admin    = 2

	permissionContractNotSet = errors.New("the permission contract address has not been set")
)

type Service struct {
	node                *node.Node
	ethClient           bind.ContractBackend
	eth                 *eth.SimpleService
	permissionContract  *Permission
	storeAbiContract    *StoreAbi
	RaftProtocolManager *backend.ProtocolManager

	stopFeed event.Feed // broadcasting stopEvent when service is being stopped

	permissionAddr common.Address
	storeAbiAddr   common.Address
	stop           chan struct{}
	watching       bool
}

func (s *Service) Start(server *p2p.Server) error {
	s.stop = make(chan struct{})
	log.Debug("permission service: starting")
	return nil
}

// SetContractAddress 设置权限合约地址
func (s *Service) SetContractAddress(addr common.Address) (bool, error) {
	if s.watching && addr != s.permissionAddr {
		close(s.stop)
		//更换合约地址
		s.permissionAddr = addr
		permission, err := NewPermission(s.permissionAddr, s.ethClient)
		if err != nil {
			return false, err
		}
		s.permissionContract = permission
		s.stop = make(chan struct{})
		go s.runPermissionVerifyNotify()
		go s.WatchNetworkInitComplete()
		time.Sleep(time.Second)
	}
	if !s.watching {
		s.permissionAddr = addr
		permission, err := NewPermission(s.permissionAddr, s.ethClient)
		if err != nil {
			return false, err
		}
		s.permissionContract = permission
		s.stop = make(chan struct{})
		go s.runPermissionVerifyNotify()
		go s.WatchNetworkInitComplete()
		time.Sleep(time.Second)
	}
	//将权限合约地址写入数据库中
	err := storeContractAddress(permissionKey, addr, s.GetCommonDb())
	if err != nil {
		return false, err
	}
	log.Info("show syncNodeId in SetContractAddress")
	s.syncNodeId()
	return true, nil
}
func (s *Service) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "permission",
			Version:   "1.0",
			Service:   NewQuorumControlsAPI(s),
			Public:    true,
		},
	}
}

// GetPermissionContract 获取权限合约实例
func (s *Service) GetPermissionContract() (*Permission, error) {
	if s.permissionContract == nil && s.permissionAddr != (common.Address{}) && s.ethClient != nil {
		permission, err := NewPermission(s.permissionAddr, s.ethClient)
		if err != nil {
			return nil, err
		}
		s.permissionContract = permission
	}
	if s.permissionContract == nil {
		return nil, errors.New("no permission contract")
	}
	return s.permissionContract, nil
}

func (s *Service) Protocols() []p2p.Protocol {
	return []p2p.Protocol{}
}

func (s *Service) Stop() error {
	log.Info("permission service: stopping")
	close(s.stop)
	log.Info("permission service: stopped")
	return nil
}

func NewQuorumControlsAPI(s *Service) *QuorumControlsAPI {
	return &QuorumControlsAPI{s}
}
func NewPermissionService(stack *node.Node, ethereum *eth.SimpleService) (*Service, error) {
	s := &Service{
		node: stack,
		eth:  ethereum,
	}
	return s, nil
}
func (s *Service) getAuth(from common.Address) (*bind.TransactOpts, error) {
	privateKey, err := s.getPrivateKey(from)
	if err != nil {
		return nil, err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, s.eth.ChainConfig().ChainID)
	if err != nil {
		return nil, err
	}
	auth.From = from
	return auth, nil
}

func (s *Service) GetAccountManager() *accounts.Manager {
	return s.eth.AccountManager()
}

func (s *Service) GetCommonDb() ethdb.Database {
	return s.eth.CommonDb()
}
func (s *Service) getPrivateKey(addr common.Address) (*ecdsa.PrivateKey, error) {
	account := accounts.Account{Address: addr}
	am := s.GetAccountManager()
	keyStore, err := fetchKeystore(am, account)
	if err != nil {
		return nil, err
	}
	privateKey, err := keyStore.GetPrivateKey(account)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
func (s *Service) getPublicKey(addr common.Address) (string, error) {
	account := accounts.Account{Address: addr}
	am := s.GetAccountManager()
	ks, err := fetchKeystore(am, account)
	if err != nil {
		return "", err
	}
	publicKey, err := ks.GetPublicKey(account)
	if err != nil {
		return "", err
	}
	return publicKey, nil
}

// Exit 自己退出网络
// leave from network by self
func (s *Service) Exit(from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	fullNodeId := s.node.Server().NodeInfo().Enode
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.Exit(auth, fullNodeId)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, err
}

func (s *Service) Prepare() error {
	log.Debug("permission service: binding contracts")
	client, err := s.node.Attach()
	if err != nil {
		log.Error("Service Prepare", "err", err)
		return err
	}
	s.ethClient = ethclient.NewClient(client)
	//read from common db
	addr, err := loadContractAddress(permissionKey, s.GetCommonDb())
	if err != nil {
		log.Error("load permission contract address", "err", err)
		return err
	}
	//if contract address exist ,then use it as permission contract address.
	if addr != (common.Address{}) {
		log.Info("use permission contract", "contract address", addr.String())
		s.permissionAddr = addr
		permission, err := NewPermission(s.permissionAddr, s.ethClient)
		if err != nil {
			return err
		}
		s.permissionContract = permission
		go s.runPermissionVerifyNotify()
		go s.WatchNetworkInitComplete()

		// add peer if node is in network
		if s.eth != nil && s.eth.ChainConfig().Clique != nil {
			go s.tryConnectNode()
		}
		log.Info("call syncNodeId in Prepare")
		s.syncNodeId()
		log.Info("permission service is now ready")
	}
	addr, err = loadContractAddress(storeAbiKey, s.GetCommonDb())
	if err != nil {
		log.Error("load store contract address", "err", err)
		return err
	}
	if addr != (common.Address{}) {
		s.storeAbiAddr = addr
		storeAbi, err := NewStoreAbi(s.storeAbiAddr, s.ethClient)
		if err != nil {
			return err
		}
		s.storeAbiContract = storeAbi
		log.Info("storeAbi service is now ready")
	}
	return nil
}

func (s *Service) unlockFirstAccount() {
	am := s.GetAccountManager()
	ks := am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	if len(am.Accounts()) == 0 {
		return
	}
	if err := ks.TimedUnlock(accounts.Account{Address: am.Accounts()[0]}, "", 0); err != nil {
		log.Warn("when start sipe, use empty passwd to unlock first account but fail", "error", err)
		return
	}
	log.Info("unlock first account success!")
}
func (s *Service) tryConnectNode() {
	if !s.isInitFinished() {
		//网络初始化还没有完成，不需要
		return
	}
	//本节点
	localNode := strings.Split(s.node.Server().NodeInfo().Enode, "@")[0]
	callOpts := &bind.CallOpts{
		Pending: true,
	}
	//从合约上查询一下自己
	nodeId, _, _, _, _, role, _, _, err := s.permissionContract.GetNodeMap(callOpts, localNode)
	if err != nil {
		log.Error("query contract failed", "err", err)
		return
	}
	//自己不在联盟中
	if nodeId == "" {
		log.Info("local node is not in network")
		return
	}
	//自己是管理节点或普通节点就可以主动去连接其他节点
	if role.Cmp(big.NewInt(int64(Normal))) == 0 || role.Cmp(big.NewInt(int64(Admin))) == 0 {
		log.Info("try connect with others")
		//query normal node and admin node in contract to connect
		nodes := s.getAvailableNodes()
		s.connectNode(nodes)
	}
}

// 连接节点
func (s *Service) connectNode(nodes string) {
	nodeArray := strings.Split(nodes, ",")
	callOpts := &bind.CallOpts{
		Pending: true,
	}
	for _, v := range nodeArray {
		if v == "" {
			continue
		}
		nodeId, ip, port, _, _, _, _, _, err := s.permissionContract.GetNodeMap(callOpts, v)
		if err != nil {
			log.Error("connect with node failed", "err", err, "nodeId", nodeId, "ip", ip, "port", port)
			continue
		}
		if nodeId == "" {
			continue
		}
		url := fmt.Sprintf("%s@%s:%s", nodeId, ip, port)
		chainNode, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			log.Error("enode.Parse failed", "error", err, "url", url)
			continue
		}
		s.node.Server().AddPeer(chainNode)
	}
}

// 获取可以连接的节点（包括普通节点和管理员节点）
func (s *Service) getAvailableNodes() string {
	var ret string
	callOpts := &bind.CallOpts{
		Pending: true,
	}
	//获取普通节点
	normalNodes, err := s.permissionContract.GetNodeByRole(callOpts, big.NewInt(int64(Normal)))
	if err != nil {
		log.Error("get normal node from contract failed", "error", err)
	}
	ret += normalNodes
	//获取管理节点
	adminNodes, err := s.permissionContract.GetNodeByRole(callOpts, big.NewInt(int64(Admin)))
	if err != nil {
		log.Error("get admin node from contract failed", "error", err)
	}
	ret += adminNodes
	return ret
}

func (s *Service) runPermissionVerifyNotify() {
	sink := make(chan *PermissionVerifyNotify, 1)
	var start uint64 = 1
	opts := &bind.WatchOpts{
		Start: &start,
	}
	filter, err := s.permissionContract.WatchVerifyNotify(opts, sink)
	if err != nil {
		log.Error(err.Error())
		return
	}
	s.watching = true
	go s.isAdminRoleEvent()
	go s.isVotedEvent()
	defer func() {
		s.watching = false
	}()
	defer filter.Unsubscribe()
	for {
		select {
		case eventObject := <-sink:
			log.Info("call syncNodeId in runPermissionVerifyNotify")
			s.syncNodeId()
			log.Info("eventObject", "nodeId", eventObject.EnodeId, "opCode", eventObject.OpCode)
			result, err := s.onPermissionNotify(eventObject)
			if err != nil || !result {
				log.Error("operate failed.", "result", result, "err", err)
			}
		case <-s.stop:
			log.Info("quit permission contract watch")
			return
		case err := <-filter.Err():
			if err != nil {
				log.Info("permission contract watch exits")
				return
			}
		}
	}
}

func (s *Service) opAllNodeOnChain(server *p2p.Server, opType int) {
	log.Info("opAllNodeOnChain", "opType", opType)
	ret1, err := s.permissionContract.GetNodeByRole(&bind.CallOpts{
		Pending: true,
	}, big.NewInt(int64(Admin)))
	if err != nil {
		log.Error("query failed", "err", err)
	}
	tmp := strings.Split(ret1, ",")
	ret2, err := s.permissionContract.GetNodeByRole(&bind.CallOpts{
		Pending: true,
	}, big.NewInt(int64(Normal)))
	if err != nil {
		log.Error("query failed", "err", err)
	}
	tmp1 := strings.Split(ret2, ",")
	tmp = append(tmp, tmp1...)
	for _, nodeId := range tmp {
		returnNodeId, ip, port, _, _, _, _, _, err := s.permissionContract.GetNodeMap(&bind.CallOpts{
			Pending: true,
		}, nodeId)
		if err != nil || returnNodeId == "" {
			log.Error("query failed", "err", err, "nodeId response", returnNodeId)
			continue
		}
		remoteNodeURL := fmt.Sprintf("%v@%v:%v", returnNodeId, ip, port)
		nodeObject, err := enode.Parse(enode.ValidSchemes, remoteNodeURL)
		if err != nil {
			log.Error("eNode.Parse failed", "error", err)
			return
		}
		if opType == Join {
			server.AddPeer(nodeObject)
		}
		if opType == Remove {
			server.RemovePeer(nodeObject)
		}
	}
}

func (s *Service) onPermissionNotify(verifyNotify *PermissionVerifyNotify) (bool, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Error("onPermissionNotify", "err", err)
		}
	}()
	// Make sure the server is running, fail otherwise
	server := s.node.Server()
	if server == nil {
		return false, fmt.Errorf("node not started")
	}

	url := fmt.Sprintf("%s@%s:%s", verifyNotify.EnodeId, verifyNotify.Ip, verifyNotify.Port)

	localeNode := s.node.Server().NodeInfo().Enode
	localeNodeId, _, _, err := splitENode(localeNode)
	if err != nil {
		return false, err
	}
	//退出联盟
	if verifyNotify.OpCode.Cmp(big.NewInt(int64(Remove))) == 0 {
		//remove from network
		// Try to remove the url as a static peer and return
		nodeObject, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid eNode: %v", err)
		}
		server.RemovePeer(nodeObject)
		if localeNodeId == verifyNotify.EnodeId {
			s.opAllNodeOnChain(server, Remove)
		}
	}
	//成功加入联盟
	if verifyNotify.OpCode.Cmp(big.NewInt(int64(Join))) == 0 {
		// Try to add the url as a static peer and return
		nodeObject, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid eNode: %v", err)
		}
		server.AddPeer(nodeObject)
		if localeNodeId == verifyNotify.EnodeId {
			s.opAllNodeOnChain(server, Join)
		}
		log.Info("onPermissionNotify before syncNodeId")
	}
	return true, nil
}

// InitFinish 完成联盟网络初始化
func (s *Service) InitFinish(from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.InitFinish(auth)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, nil
}

// SetAdminNode 设置管理员节点
func (s *Service) SetAdminNode(fullNodeId string, nodeName string, address common.Address, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	nodeId, ip, port, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	//todo verify ip and port
	tx, err := s.permissionContract.SetAdminNode(auth, nodeId, ip, port, nodeName, address)
	if err != nil {
		return result, err
	}
	log.Debug("permission:set a new admin node", "nodeId", nodeId, "nodeName", nodeName)
	result = tx.Hash().String()
	return result, nil
}

// MakeProposalForAdmin 申请成为管理节点
func (s *Service) MakeProposalForAdmin(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	opAdmin := "2"
	tx, err := s.permissionContract.MakeProposeForRoleChange(auth, nodeId, opAdmin, localNodeId)
	if err != nil {
		return result, err
	}
	log.Debug("permission:proposal to make an admin node", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// AcceptProposalForAdmin 节点升级投赞成票
func (s *Service) AcceptProposalForAdmin(fullNodeId string, from common.Address) (string, error) {
	result := ""
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	//2 升级为管理节点
	opAdmin := "2"
	tx, err := s.permissionContract.VoteForRoleChange(auth, nodeId, localNodeId, opAdmin)
	if err != nil {
		return result, err
	}
	log.Debug("permission:voting for node upgrading to admin", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// MakeProposalForCommon 申请成为普通节点
func (s *Service) MakeProposalForCommon(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	// 3 降级成普通节点
	opCommon := "3"
	tx, err := s.permissionContract.MakeProposeForRoleChange(auth, nodeId, opCommon, localNodeId)
	if err != nil {
		return result, err
	}
	log.Debug("permission:proposal to make a normal node", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// AcceptProposalForCommon 节点降级投票
// 使用fullNodeId和nodeAddress绑定组成一个节点的唯一标识
func (s *Service) AcceptProposalForCommon(fullNodeId string, from common.Address) (string, error) {
	result := ""
	//本节点
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	// 3 降级成普通节点
	var opCommon string = "3"
	tx, err := s.permissionContract.VoteForRoleChange(auth, nodeId, localNodeId, opCommon)
	if err != nil {
		return result, err
	}
	log.Debug("permission:voting for node degrading to normal", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// MakeProposalForExit 发起退出联盟提案
func (s *Service) MakeProposalForExit(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	opExit := "1"
	tx, err := s.permissionContract.MakeProposeForRoleChange(auth, nodeId, opExit, localNodeId)
	if err != nil {
		return result, err
	}
	log.Debug("permission:proposal to exclude a node", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// AcceptProposalForExit 变成游离节点（退出联盟）
func (s *Service) AcceptProposalForExit(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	// 1 退出联盟，也就是变成游离节点
	opExit := "1"
	tx, err := s.permissionContract.VoteForRoleChange(auth, nodeId, localNodeId, opExit)
	if err != nil {
		return result, err
	}
	log.Debug("permission:voting for excluding node", "nodeId", nodeId, "txHash", tx.Hash().String())
	result = tx.Hash().String()
	return result, err
}

// MakeProposalForJoin 申请加入联盟
// add new node application
func (s *Service) MakeProposalForJoin(fullNodeId string, nodeName string, nodeAddress common.Address, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, ip, port, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.MakeProposeForAddNewNode(auth, nodeId, ip, port, nodeName, nodeAddress, localNodeId)
	if err != nil {
		return result, err
	}
	log.Debug("permission:proposal to add a node", "nodeId", nodeId, "txHash", tx.Hash().String())
	return tx.Hash().String(), err
}

// AcceptProposalForJoin 对申请加入联盟进行投赞成票
// AcceptProposalForJoin
func (s *Service) AcceptProposalForJoin(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.VoteForNewNodeApply(auth, nodeId, localNodeId)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	log.Debug("permission:voting for node adding", "nodeId", nodeId, "txHash", tx.Hash().String())
	return result, err
}

// UpdateNodeInfo 更新节点信息
// 只能自己更新
// update node info
func (s *Service) UpdateNodeInfo(from common.Address, ip, port string) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.UpdateNodeInfo(auth, localNodeId, ip, port)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, err
}
func (s *Service) UpdateNodeName(fullNodeId string, nodeName string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	temp := strings.Split(fullNodeId, "@")
	nodeId := temp[0]
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.UpdateNodeName(auth, nodeId, nodeName)
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, err
}

// Disagree 投反对票
// 包括加入，升级，降级
func (s *Service) Disagree(fullNodeId string, opCode int, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	localFullNodeId := s.node.Server().NodeInfo().Enode
	temp := strings.Split(localFullNodeId, "@")
	localNodeId := temp[0]
	auth, err := s.getAuth(from)
	if err != nil {
		return result, err
	}
	nodeId, _, _, err := splitENode(fullNodeId)
	if err != nil {
		return result, err
	}
	tx, err := s.permissionContract.Disagree(auth, nodeId, localNodeId, fmt.Sprintf("%d", opCode))
	if err != nil {
		return result, err
	}
	result = tx.Hash().String()
	return result, err
}

// GetNodeByRole 根据角色类型获取节点
func (s *Service) GetNodeByRole(role *big.Int, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	opts := &bind.CallOpts{From: from}
	ret, err := s.permissionContract.GetNodeByRole(opts, role)
	if err != nil {
		return result, err
	}
	return ret, nil
}

// GetNodeRole 获取节点的角色
//
//	//管理节点
//	uint admin=2;
//	//普通节点
//	uint common=0;
//	//游离节点
//	uint isolated=1;
func (s *Service) GetNodeRole(fullNodeId string, from common.Address) (*big.Int, error) {
	result := big.NewInt(0)
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	nodeId := strings.Split(fullNodeId, "@")[0]
	opts := &bind.CallOpts{From: from}
	eNodeRet, _, _, _, _, role, _, _, err := s.permissionContract.GetNodeMap(opts, nodeId)
	if err != nil || eNodeRet == "" {
		if err != nil {
			log.Error("Service GetNodeRole", "eNodeId err", err.Error())
			return big.NewInt(3), fmt.Errorf("GetNodeRole query failed %s", err.Error())
		}
		return big.NewInt(3), fmt.Errorf("GetNodeRole query failed")
	}
	return role, nil
}

// GetNodeInfoByName 通过节点名称获取节点信息
func (s *Service) GetNodeInfoByName(nodeName string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	opts := &bind.CallOpts{From: from}
	nodeId, ip, port, _, address, role, ifMiner, createdAt, err := s.permissionContract.GetInfoByName(opts, nodeName)
	if err != nil {
		return result, err
	}
	if nodeId == "" {
		return result, errors.New("node not exists")
	}
	return fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v", nodeId, ip, port, nodeName, address.String(), role, ifMiner, createdAt), nil
}

func (s *Service) GetStateMap(fullNodeId string, opCode string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	opts := &bind.CallOpts{From: from}

	nodeId := strings.Split(fullNodeId, "@")[0]

	agree, disagree, proposeNodeId, opCode, status, err := s.permissionContract.GetLastStatistics(opts, nodeId, opCode)

	if err != nil || proposeNodeId == "" {
		return "", fmt.Errorf("GetStateMap query failed")
	}
	return fmt.Sprintf("%v,%v,%v,%v,%v", agree, disagree, proposeNodeId, opCode, status), nil
}

func (s *Service) GetNodeInfo(fullNodeId string, from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	opts := &bind.CallOpts{From: from}
	nodeId := strings.Split(fullNodeId, "@")[0]
	returnNodeId, ip, port, nodeName, eNodeAddress, role, ifMiner, createdAt, err := s.permissionContract.GetNodeMap(opts, nodeId)
	if err != nil {
		return result, fmt.Errorf("GetNodeInfo query failed")
	}
	if returnNodeId == "" {
		result = "the node is not a member of the alliance"
		return result, nil
	}
	return fmt.Sprintf("%s,%s,%s,%s,%s,%v,%v,%v", returnNodeId, ip, port, nodeName, eNodeAddress.String(), role, ifMiner, createdAt), nil
}
func (s *Service) GetAllStatingRecord(from common.Address) (string, error) {
	result := ""
	if s.permissionContract == nil {
		return result, permissionContractNotSet
	}
	opts := &bind.CallOpts{From: from}
	stateKeys, err := s.permissionContract.GetAllStatingRecord(opts)
	if err != nil {
		return result, err
	}
	return stateKeys, nil
}

func (s *Service) IsAdmin(fullNodeId string, from common.Address) (bool, error) {
	if s.permissionContract == nil {
		return false, permissionContractNotSet
	}
	nodeId := strings.Split(fullNodeId, "@")[0]
	opts := &bind.CallOpts{From: from}
	h := crypto.Keccak256Hash([]byte(nodeId))
	flag, err := s.permissionContract.IsAdmin(opts, h)
	if err != nil {
		return false, err
	}
	return flag, nil
}

// AddPeer 添加节点
func (s *Service) AddPeer(url string, from common.Address) (bool, error) {
	//本节点
	localNode := s.node.Server().NodeInfo().Enode
	if s.node.Config().EnableNodePermission {
		available, err := s.verifyPermission(url, from)
		if err != nil {
			log.Error("verify permission failed", "url", url, "err", err)
			return false, err
		}
		if !available {
			return false, errors.New(fmt.Sprintf("the node %s does not join the network", url))
		}
		available, err = s.verifyPermission(localNode, from)
		if err != nil {
			log.Error("verify permission failed", "url", localNode, "err", err)
			return false, err
		}
		if !available {
			return false, errors.New(fmt.Sprintf("local %s does not join the network", localNode))
		}
	}
	if s.eth != nil && s.eth.ChainConfig().Clique != nil {
		// Make sure the server is running, fail otherwise
		server := s.node.Server()
		if server == nil {
			return false, fmt.Errorf("node not started")
		}
		// Try to add the url as a static peer and return
		nodeObject, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid enode: %v", err)
		}
		server.AddPeer(nodeObject)
	}
	return true, nil
}

func (s *Service) RemovePeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	if s.eth.ChainConfig().Clique != nil { //poa
		server := s.node.Server()
		if server == nil {
			return false, fmt.Errorf("node not started")
		}
		// Try to remove the url as a static peer and return
		nodeObject, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid enode: %v", err)
		}
		server.RemovePeer(nodeObject)
	}
	return true, nil
}

func (s *Service) verifyPermission(url string, from common.Address) (bool, error) {
	nodeId, _, _, err := splitENode(url)
	if err != nil {
		return false, err
	}
	if s.permissionContract == nil {
		return false, permissionContractNotSet
	}

	opts := &bind.CallOpts{From: from}
	returnNodeId, _, _, _, _, role, _, _, err := s.permissionContract.GetNodeMap(opts, nodeId)
	if err != nil {
		return false, err
	}
	if returnNodeId == "" {
		return false, errors.New("the node is isolated node")
	}
	if role.Cmp(big.NewInt(int64(Isolated))) == 0 {
		return false, errors.New("the node can not join network")
	}
	return true, nil
}
func (s *Service) WatchNetworkInitComplete() {
	sink := make(chan *PermissionNetworkInitComplete, 1)
	var start uint64 = 1
	opts := &bind.WatchOpts{
		Start: &start,
	}
	filter, err := s.permissionContract.WatchNetworkInitComplete(opts, sink)
	if err != nil {
		log.Error(err.Error())
		return
	}
	defer filter.Unsubscribe()
	for {
		select {
		case initCompleteEvent := <-sink:
			log.Info("WatchNetworkInitComplete", "block number", initCompleteEvent.Number)
			log.Info("call syncNodeId in WatchNetworkInitComplete")
			s.syncNodeId()
			s.CacheManager()
		case <-s.stop:
			log.Info("quit permission contract watch")
			return
		case err := <-filter.Err():
			if err != nil {
				log.Error("permission contract watch exits", "error", err)
				return
			}
		}
	}
}

func (s *Service) CacheManager() {
	//获取管理员节点
	role := big.NewInt(0).SetInt64(int64(Admin))
	am := s.GetAccountManager()
	//获取所有的管理员节点
	nodeIdStr, err := s.GetNodeByRole(role, am.Accounts()[0])
	if err != nil {
		log.Error("GetAllNode", "err", err)
		return
	}
	nodeIds := strings.Split(nodeIdStr, ",")
	for _, nodeId := range nodeIds {
		callOpts := &bind.CallOpts{
			Pending: true,
		}
		_, _, _, _, addr, _, isOriginator, _, err := s.permissionContract.GetNodeMap(callOpts, nodeId)
		if err != nil {
			log.Error("GetNodeMap", "error", err)
			continue
		}
		//缓存所有的创世管理员
		if addr != (common.Address{}) && isOriginator {
			log.Debug("CacheManager", "addr", addr.String())
			s.eth.GetSuperManager().AddManager(addr)
		}
	}
}
func (s *Service) isInitFinished() bool {
	if s.permissionContract == nil {
		return false
	}
	finish, err := s.permissionContract.IsInitFinished(&bind.CallOpts{
		Pending: true,
	})
	if err != nil {
		log.Error("Service IsInitFinished", "err", err.Error())
		return false
	}
	return finish
}
func (s *Service) GetAdminCount() (*big.Int, error) {
	if s.permissionContract == nil {
		return big.NewInt(0), errors.New("permission Contract is nil")
	}
	count, err := s.permissionContract.GetAdminCount(&bind.CallOpts{
		Pending: true,
	})
	if err != nil {
		log.Error("Service GetAdminCount", "err", err.Error())
		return big.NewInt(0), err
	}
	return count, nil
}
func (s *Service) nodeExists(fullNodeId string) bool {
	if s.permissionContract == nil {
		return false
	}
	nodeId := strings.Split(fullNodeId, "@")[0]
	opts := &bind.CallOpts{Pending: true}
	exists, err := s.permissionContract.NodeExists(opts, nodeId)
	if err != nil {
		log.Error("Service nodeExists", "err", err.Error())
		return false
	}
	return exists
}
func (s *Service) SetInitFinishedFlag(db ethdb.Database) error {
	return db.Put([]byte(common.PermissionInitFinished), []byte("true"))
}

func (s *Service) cacheNodeId(nodeId string, db ethdb.Database) error {
	log.Info("cacheNodeId", "nodeId", nodeId)
	return db.Put([]byte(nodeId), []byte("true"))
}

// filterNodeId nodeId形如 "enode://217d5b...928b@101.68.74.170:30303"
// 取 217d5b...928b
func (s *Service) filterNodeId(nodeId string) string {
	if strings.Contains(nodeId, "enode://") {
		nodeId = strings.ReplaceAll(nodeId, "enode://", "")
	}
	if strings.Contains(nodeId, "@") {
		strArr := strings.Split(nodeId, "@")
		nodeId = strArr[0]
	}
	return nodeId
}

// 同步节点
func (s *Service) syncNodeId() {
	if s.isInitFinished() {
		err := s.SetInitFinishedFlag(s.GetCommonDb())
		if err != nil {
			log.Error("SetInitFinishedFlag", "err", err.Error())
		}
		//游离节点要删除
		nodeString := s.dissociateNodes()
		if nodeString != "" {
			log.Info("syncNodeId", "dissociateNodes", nodeString)
			nodeArr := strings.Split(nodeString, ",")
			for _, v := range nodeArr {
				if v == "" {
					continue
				}
				err := s.removeNodeId(s.filterNodeId(v), s.GetCommonDb())
				if err != nil {
					log.Error("removeNodeId", "err", err.Error())
				}
			}
		}
		//正常节点要缓存
		nodeStr := s.getAvailableNodes()
		if nodeStr != "" {
			log.Info("syncNodeId", "availableNodes", nodeStr)
			nodeArray := strings.Split(nodeStr, ",")
			for _, v := range nodeArray {
				if v == "" {
					continue
				}
				err := s.cacheNodeId(s.filterNodeId(v), s.GetCommonDb())
				if err != nil {
					log.Error("CacheNodeId", "err", err.Error())
				}
			}
		}
	}
}

// 从db中删除节点id
func (s *Service) removeNodeId(nodeId string, db ethdb.Database) error {
	return db.Delete([]byte(nodeId))
}

// 获取游离节点
func (s *Service) dissociateNodes() string {
	var ret string
	callOpts := &bind.CallOpts{
		Pending: true,
	}
	//获取游离节点
	normalNodes, err := s.permissionContract.GetNodeByRole(callOpts, big.NewInt(int64(Isolated)))
	if err != nil {
		log.Error("get normal node from contract failed", "error", err)
	}
	ret += normalNodes
	return ret
}
func (s *Service) isAdminRoleEvent() {
	log.Info(" isAdminRoleEvent enter")
	sink := make(chan *PermissionIsAdminRoleEvent, 1)
	var start uint64 = 1
	opts := &bind.WatchOpts{
		Start: &start,
	}
	filter, err := s.permissionContract.WatchIsAdminRoleEvent(opts, sink)
	if err != nil {
		log.Error(err.Error())
		return
	}
	defer filter.Unsubscribe()
	for {
		select {
		case eventObject := <-sink:
			log.Info("call isAdminRoleEvent")
			log.Info("eventObject", "voteNodeId", eventObject.NodeId, "sender", eventObject.Sender)

		case <-s.stop:
			log.Info("quit permission contract watch")
			return
		case err := <-filter.Err():
			if err != nil {
				log.Info("permission contract watch exits")
				return
			}
		}
	}
}

func (s *Service) isVotedEvent() {
	log.Info(" isVotedEvent enter")
	sink := make(chan *PermissionIsVotedEvent, 1)
	var start uint64 = 1
	opts := &bind.WatchOpts{
		Start: &start,
	}
	filter, err := s.permissionContract.WatchIsVotedEvent(opts, sink)
	if err != nil {
		log.Error(err.Error())
		return
	}

	defer filter.Unsubscribe()
	for {
		select {
		case eventObject := <-sink:
			log.Info("call isVotedEvent")
			log.Info("eventObject", "nodeId", eventObject.NodeId, "voteId", eventObject.VoterNodeId)
		case <-s.stop:
			log.Info("quit permission contract watch")
			return
		case err := <-filter.Err():
			if err != nil {
				log.Info("permission contract watch exits")
				return
			}
		}
	}
}
