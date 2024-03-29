package eth

import (
	"errors"
	"fmt"
	"github.com/bigzoro/my_simplechain/core/access_contoller"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/bigzoro/my_simplechain/accounts"
	"github.com/bigzoro/my_simplechain/accounts/abi/bind"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/common/hexutil"
	"github.com/bigzoro/my_simplechain/consensus"
	"github.com/bigzoro/my_simplechain/consensus/clique"
	"github.com/bigzoro/my_simplechain/consensus/ethash"
	"github.com/bigzoro/my_simplechain/consensus/hotstuff"
	"github.com/bigzoro/my_simplechain/consensus/pbft"
	pbftBackend "github.com/bigzoro/my_simplechain/consensus/pbft/backend"
	"github.com/bigzoro/my_simplechain/consensus/raft"
	"github.com/bigzoro/my_simplechain/consensus/scrypt"
	"github.com/bigzoro/my_simplechain/core"
	"github.com/bigzoro/my_simplechain/core/bloombits"
	"github.com/bigzoro/my_simplechain/core/rawdb"
	"github.com/bigzoro/my_simplechain/core/types"
	"github.com/bigzoro/my_simplechain/core/vm"
	"github.com/bigzoro/my_simplechain/eth/downloader"
	"github.com/bigzoro/my_simplechain/eth/filters"
	"github.com/bigzoro/my_simplechain/eth/gasprice"
	"github.com/bigzoro/my_simplechain/ethdb"
	"github.com/bigzoro/my_simplechain/event"
	"github.com/bigzoro/my_simplechain/internal/ethapi"
	"github.com/bigzoro/my_simplechain/log"
	"github.com/bigzoro/my_simplechain/miner"
	"github.com/bigzoro/my_simplechain/node"
	"github.com/bigzoro/my_simplechain/p2p"
	"github.com/bigzoro/my_simplechain/p2p/enr"
	"github.com/bigzoro/my_simplechain/params"
	"github.com/bigzoro/my_simplechain/rlp"
	"github.com/bigzoro/my_simplechain/rpc"
)

type LesServer interface {
	Start(p2pServer *p2p.Server)
	Stop()
	APIs() []rpc.API
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
	SetContractBackend(bind.ContractBackend)
}

// SimpleService implements the SimpleService full node service.
type SimpleService struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan chan bool

	// Handlers
	txPool     *core.TxPool
	blockchain *core.BlockChain
	handler    *handler
	lesServer  LesServer

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	commonDb ethdb.Database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner    *miner.Miner
	gasPrice *big.Int

	signer common.Address

	networkID uint64

	netRPCService *ethapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and signer)

	accessControl access_contoller.AccessControlProvider
}

func (s *SimpleService) ChainConfig() *params.ChainConfig {
	return s.chainConfig
}

func (s *SimpleService) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// SetContractBackend SetClient sets a rpc client which connecting to our local node.
func (s *SimpleService) SetContractBackend(backend bind.ContractBackend) {
	// Pass the rpc client to les server if it is enabled.
	if s.lesServer != nil {
		s.lesServer.SetContractBackend(backend)
	}
}

// New creates a new SimpleService object (including the
// initialisation of the common SimpleService object)
func New(ctx *node.ServiceContext, config *Config) (*SimpleService, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.SimpleService in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", DefaultConfig.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(DefaultConfig.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		config.TrieCleanCache += config.TrieDirtyCache
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Assemble the SimpleService object
	chainDb, err := ctx.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/")
	if err != nil {
		return nil, err
	}
	commonDb, err := ctx.OpenDatabase("common", config.DatabaseCache, config.DatabaseHandles, "eth/db/common/")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlockWithOverride(chainDb, config.Genesis, config.OverrideSingularity)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	eth := &SimpleService{
		config:         config,
		chainConfig:    chainConfig,
		chainDb:        chainDb,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, chainConfig, config, config.Miner.Notify, config.Miner.Noverify, chainDb),
		shutdownChan:   make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.Miner.GasPrice,
		signer:         config.Miner.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks, params.BloomConfirms),
		commonDb:       commonDb,
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising SimpleService protocol", "versions", ProtocolVersions, "network", config.NetworkId, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
			EWASMInterpreter:        config.EWASMInterpreter,
			EVMInterpreter:          config.EVMInterpreter,
		}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
		}
	)

	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, eth.engine, vmConfig, eth.shouldPreserve)
	if err != nil {
		return nil, err
	}
	if _, ok := eth.engine.(*hotstuff.Council); ok {
		config.Hotstuff.ChainReader = eth.blockchain
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	blockChainCache := core.NewBlockChainCache(eth.blockchain)
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, chainConfig, eth.blockchain)

	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit
	checkpoint := config.Checkpoint
	if checkpoint == nil {
		checkpoint = params.TrustedCheckpoints[genesisHash]
	}

	var pbs priorBroadcastSelector
	pbs, _ = eth.engine.(priorBroadcastSelector)
	if eth.handler, err = NewHandler(chainConfig, checkpoint, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb, cacheLimit, config.Whitelist, pbs); err != nil {
		return nil, err
	}
	eth.handler.SetCommonDb(commonDb)
	eth.handler.SetNeedCheckPermission(config.NeedCheckPermission)
	eth.miner = miner.New(eth, &config.Miner, chainConfig, eth.EventMux(), eth.engine, eth.isLocalBlock, blockChainCache)
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))

	eth.APIBackend = &EthAPIBackend{ctx.ExtRPCEnabled(), eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	//eth.accessControl, err = access_contoller.NewACProvider(eth.chainConfig, "")
	if err != nil {
		panic(err)
	}

	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"sipe",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateConsensusEngine creates the required type of consensus engine instance for an SimpleService service
func CreateConsensusEngine(ctx *node.ServiceContext, chainConfig *params.ChainConfig, config *Config, notify []string, noverify bool, db ethdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}

	// Set up Hotstuff consensus engine
	if chainConfig.Hotstuff != nil {
		// snap, _ := hotstuff.LoadHeadSnapshot(db)

		legal := hotstuff.NewLegal(db)
		// legal.Import(snap)

		if !config.Hotstuff.Mine {
			return legal
		}
		council := hotstuff.NewCouncil(legal, config.Hotstuff.Id, config.Hotstuff.Key)
		config.Hotstuff.ServiceMaker = council.MakeService
		return council
	}

	if chainConfig.Scrypt != nil {
		// Scrypt and Ethash share the PowMode in this switch cases
		switch config.Ethash.PowMode {
		case ethash.ModeFake:
			log.Warn("Scrypt used in fake mode")
			return scrypt.NewFaker()
		case ethash.ModeTest:
			log.Warn("Scrypt used in test mode")
			return scrypt.NewTester(notify, noverify)
		default:
			engine := scrypt.NewScrypt(scrypt.Config{PowMode: scrypt.ModeNormal}, notify, noverify)
			engine.SetThreads(-1) // Disable CPU mining
			return engine
		}
	}
	if chainConfig.Pbft != nil {
		pbftConfig := &pbft.Config{}
		if chainConfig.Pbft.Epoch != 0 {
			pbftConfig.Epoch = chainConfig.Pbft.Epoch
		}
		pbftConfig.ProposerPolicy = pbft.ProposerPolicy(chainConfig.Pbft.ProposerPolicy)
		return pbftBackend.New(&config.Pbft, ctx.NodeKey(), db)
	}

	if chainConfig.Raft {
		return raft.New(ctx.NodeKey())
	}

	// Otherwise assume proof-of-work
	switch config.Ethash.PowMode {
	case ethash.ModeFake:
		log.Warn("Ethash used in fake mode")
		return ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		return ethash.NewTester(nil, noverify)
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		return ethash.NewShared()
	default:
		engine := ethash.New(ethash.Config{
			CacheDir:       ctx.ResolvePath(config.Ethash.CacheDir),
			CachesInMem:    config.Ethash.CachesInMem,
			CachesOnDisk:   config.Ethash.CachesOnDisk,
			DatasetDir:     config.Ethash.DatasetDir,
			DatasetsInMem:  config.Ethash.DatasetsInMem,
			DatasetsOnDisk: config.Ethash.DatasetsOnDisk,
		}, notify, noverify)
		engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *SimpleService) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the les server
	if s.lesServer != nil {
		apis = append(apis, s.lesServer.APIs()...)
	}
	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append any APIs exposed explicitly by the les server
	if s.lesServer != nil {
		apis = append(apis, s.lesServer.APIs()...)
	}

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.handler.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *SimpleService) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *SimpleService) GetSigner() (common.Address, error) {
	s.lock.RLock()
	signer := s.signer
	s.lock.RUnlock()
	//如果是主动设置了，则直接返回
	if signer != (common.Address{}) {
		return signer, nil
	}
	//如果解锁了一定的账户，则自动取第一个账户设置
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if loadAccounts := wallets[0].Accounts(); len(loadAccounts) > 0 {
			signer := loadAccounts[0].Address
			s.lock.Lock()
			s.signer = signer
			s.lock.Unlock()
			log.Info("GetSigner automatically configured", "address", signer)
			return signer, nil
		}
	}
	return common.Address{}, fmt.Errorf("signer must be explicitly specified")
}

// isLocalBlock checks whether the specified block is mined
// by local miner accounts.
//
// We regard two types of accounts as local miner account: signer
// and accounts specified via `txpool.locals` flag.
func (s *SimpleService) isLocalBlock(block *types.Block) bool {
	author, err := s.engine.Author(block.Header())
	if err != nil {
		log.Warn("Failed to retrieve block author", "number", block.NumberU64(), "hash", block.Hash(), "err", err)
		return false
	}
	// Check whether the given address is signer.
	s.lock.RLock()
	signer := s.signer
	s.lock.RUnlock()
	if author == signer {
		return true
	}
	// Check whether the given address is specified by `txpool.local`
	// CLI flag.
	for _, account := range s.config.TxPool.Locals {
		if account == author {
			return true
		}
	}
	return false
}

// shouldPreserve checks whether we should preserve the given block
// during the chain reorg depending on whether the author of block
// is a local account.
func (s *SimpleService) shouldPreserve(block *types.Block) bool {
	// The reason we need to disable the self-reorg preserving for clique
	// is it can be probable to introduce a deadlock.
	//
	// e.g. If there are 7 available signers
	//
	// r1   A
	// r2     B
	// r3       C
	// r4         D
	// r5   A      [X] F G
	// r6    [X]
	//
	// In the round5, the inturn signer E is offline, so the worst case
	// is A, F and G sign the block of round5 and reject the block of opponents
	// and in the round6, the last available signer B is offline, the whole
	// network is stuck.
	if _, ok := s.engine.(*clique.Clique); ok {
		return false
	}
	return s.isLocalBlock(block)
}

// SetSigner sets the mining reward address.
func (s *SimpleService) SetSigner(signer common.Address) {
	s.lock.Lock()
	s.signer = signer
	s.lock.Unlock()

	s.miner.SetEtherbase(signer)
}

// StartMining starts the miner with the given number of CPU threads. If mining
// is already running, this method adjust the number of threads allowed to use
// and updates the minimum price required by the transaction pool.
func (s *SimpleService) StartMining(threads int) error {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		log.Info("Updated mining threads", "threads", threads)
		if threads == 0 {
			threads = -1 // Disable the miner from within
		}
		th.SetThreads(threads)
	}
	// If the miner was not running, initialize it
	if !s.IsMining() {
		// Propagate the initial price point to the transaction pool
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)

		// Configure the local mining address
		eb, err := s.GetSigner()
		if err != nil {
			log.Error("Cannot start mining without signer", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		if cliqueEngine, ok := s.engine.(*clique.Clique); ok {
			wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
			if wallet == nil || err != nil {
				log.Error("GetSigner account unavailable locally", "err", err)
				return fmt.Errorf("signer missing: %v", err)
			}
			cliqueEngine.Authorize(eb, wallet.SignData)
		}
		// If mining is started, we can disable the transaction rejection mechanism
		// introduced to speed sync times.
		atomic.StoreUint32(&s.handler.acceptTxs, 1)
		go s.miner.Start(eb)
	}
	return nil
}

// StopMining terminates the miner, both at the consensus engine level as well as
// at the block creation level.
func (s *SimpleService) StopMining() {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	// Stop the block creating itself
	s.miner.Stop()
}

func (s *SimpleService) IsMining() bool      { return s.miner.Mining() }
func (s *SimpleService) Miner() *miner.Miner { return s.miner }

func (s *SimpleService) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *SimpleService) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *SimpleService) TxPool() *core.TxPool               { return s.txPool }
func (s *SimpleService) EventMux() *event.TypeMux           { return s.eventMux }
func (s *SimpleService) Engine() consensus.Engine           { return s.engine }
func (s *SimpleService) ChainDb() ethdb.Database            { return s.chainDb }
func (s *SimpleService) IsListening() bool                  { return true } // Always listening
func (s *SimpleService) EthVersion() int                    { return int(ProtocolVersions[0]) }
func (s *SimpleService) NetVersion() uint64                 { return s.networkID }
func (s *SimpleService) Downloader() *downloader.Downloader { return s.handler.downloader }
func (s *SimpleService) Synced() bool                       { return atomic.LoadUint32(&s.handler.acceptTxs) == 1 }
func (s *SimpleService) ArchiveMode() bool                  { return s.config.NoPruning }
func (s *SimpleService) GetEthConfig() *Config              { return s.config }
func (s *SimpleService) GetSynced() func() bool             { return s.Synced }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *SimpleService) Protocols() []p2p.Protocol {
	protocols := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protocols[i] = s.handler.makeProtocol(vsn)
		protocols[i].Attributes = []enr.Entry{s.currentEthEntry()}
	}
	if s.lesServer != nil {
		protocols = append(protocols, s.lesServer.Protocols()...)
	}
	return protocols
}

// Start implements node.Service, starting all internal goroutines needed by the
// SimpleService protocol implementation.
func (s *SimpleService) Start(p2pServer *p2p.Server) error {
	s.startEthEntryUpdate(p2pServer.LocalNode())

	// Start the bloom bits servicing goroutines
	s.startBloomHandlers(params.BloomBitsBlocks)

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(p2pServer, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := p2pServer.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= p2pServer.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, p2pServer.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.handler.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(p2pServer)
	}
	s.handler.SubscribeCertificateEvent(p2pServer.GetCertificateCh())
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// SimpleService protocol.
func (s *SimpleService) Stop() error {
	err := s.bloomIndexer.Close()
	if err != nil {
		log.Error("SimpleService bloomIndexer", "err", err)
	}
	s.blockchain.Stop()
	err = s.engine.Close()
	if err != nil {
		log.Error("SimpleService engine", "err", err)
	}
	s.handler.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Stop()
	s.eventMux.Stop()

	err = s.chainDb.Close()
	if err != nil {
		log.Error("SimpleService chainDb", "err", err)
	}
	err = s.commonDb.Close()
	if err != nil {
		log.Error("SimpleService commonDb", "err", err)
	}
	close(s.shutdownChan)
	return nil
}

func (s *SimpleService) GetSuperManager() *SuperManager {
	return s.handler.superManager
}

func (s *SimpleService) CommonDb() ethdb.Database {
	return s.commonDb
}
