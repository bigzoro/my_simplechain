// Copyright 2017 The go-simplechain Authors
// This file is part of go-simplechain.
//
// go-simplechain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-simplechain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-simplechain. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"unicode"

	"github.com/simplechain-org/go-simplechain/cmd/utils"
	"github.com/simplechain-org/go-simplechain/consensus/raft"
	raftBackend "github.com/simplechain-org/go-simplechain/consensus/raft/backend"
	"github.com/simplechain-org/go-simplechain/eth"
	"github.com/simplechain-org/go-simplechain/log"
	"github.com/simplechain-org/go-simplechain/monitor"
	"github.com/simplechain-org/go-simplechain/node"
	"github.com/simplechain-org/go-simplechain/p2p/enode"
	"github.com/simplechain-org/go-simplechain/params"
	whisper "github.com/simplechain-org/go-simplechain/whisper/whisperv6"

	"github.com/naoina/toml"
	"gopkg.in/urfave/cli.v1"
)

var (
	dumpConfigCommand = cli.Command{
		Action:      utils.MigrateFlags(dumpConfig),
		Name:        "dumpconfig",
		Usage:       "Show configuration values",
		ArgsUsage:   "",
		Flags:       append(append(nodeFlags, rpcFlags...), whisperFlags...),
		Category:    "MISCELLANEOUS COMMANDS",
		Description: `The dumpconfig command shows configuration values.`,
	}

	configFileFlag = cli.StringFlag{
		Name:  "config",
		Usage: "TOML configuration file",
	}
)

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		link := ""
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

type ethstatsConfig struct {
	URL string `toml:",omitempty"`
}

type gethConfig struct {
	Eth      eth.Config
	Shh      whisper.Config
	Node     node.Config
	Ethstats ethstatsConfig
}

func loadConfig(file string, cfg *gethConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}

func defaultNodeConfig() node.Config {
	cfg := node.DefaultConfig
	cfg.Name = clientIdentifier
	cfg.Version = params.VersionWithCommit(gitCommit, gitDate)
	cfg.HTTPModules = append(cfg.HTTPModules, "eth", "shh")
	cfg.WSModules = append(cfg.WSModules, "eth", "shh")
	cfg.IPCPath = "sipe.ipc"
	return cfg
}

func makeConfigNode(ctx *cli.Context) (*node.Node, gethConfig) {
	// Load defaults.
	cfg := gethConfig{
		Eth:  eth.DefaultConfig,
		Shh:  whisper.DefaultConfig,
		Node: defaultNodeConfig(),
	}

	// Load config file.
	if file := ctx.GlobalString(configFileFlag.Name); file != "" {
		if err := loadConfig(file, &cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// Apply flags.
	utils.SetNodeConfig(ctx, &cfg.Node)
	stack, err := node.New(&cfg.Node)
	if err != nil {
		utils.Fatalf("Failed to create the protocol stack: %v", err)
	}
	utils.SetEthConfig(ctx, stack, &cfg.Eth)
	if ctx.GlobalIsSet(utils.EthStatsURLFlag.Name) {
		cfg.Ethstats.URL = ctx.GlobalString(utils.EthStatsURLFlag.Name)
	}
	utils.SetShhConfig(ctx, stack, &cfg.Shh)
	return stack, cfg
}

// enableWhisper returns true in case one of the whisper flags is set.
func enableWhisper(ctx *cli.Context) bool {
	for _, flag := range whisperFlags {
		if ctx.GlobalIsSet(flag.GetName()) {
			return true
		}
	}
	return false
}

func makeFullNode(ctx *cli.Context) *node.Node {
	stack, cfg := makeConfigNode(ctx)
	if ctx.GlobalIsSet(utils.OverrideSingularityFlag.Name) {
		cfg.Eth.OverrideSingularity = new(big.Int).SetUint64(ctx.GlobalUint64(utils.OverrideSingularityFlag.Name))
	}
	cfg.Eth.NeedCheckPermission = ctx.GlobalBool(utils.EnableNodePermissionFlag.Name)
	mainCh, raftCh := utils.RegisterEthService(stack, &cfg.Eth)

	// Whisper must be explicitly enabled by specifying at least 1 whisper flag or in dev mode
	shhEnabled := enableWhisper(ctx)
	shhAutoEnabled := !ctx.GlobalIsSet(utils.WhisperEnabledFlag.Name) && ctx.GlobalIsSet(utils.DeveloperFlag.Name)
	if shhEnabled || shhAutoEnabled {
		if ctx.GlobalIsSet(utils.WhisperMaxMessageSizeFlag.Name) {
			cfg.Shh.MaxMessageSize = uint32(ctx.Int(utils.WhisperMaxMessageSizeFlag.Name))
		}
		if ctx.GlobalIsSet(utils.WhisperMinPOWFlag.Name) {
			cfg.Shh.MinimumAcceptedPOW = ctx.Float64(utils.WhisperMinPOWFlag.Name)
		}
		if ctx.GlobalIsSet(utils.WhisperRestrictConnectionBetweenLightClientsFlag.Name) {
			cfg.Shh.RestrictConnectionBetweenLightClients = true
		}
		utils.RegisterShhService(stack, &cfg.Shh)
	}
	// Configure GraphQL if requested
	if ctx.GlobalIsSet(utils.GraphQLEnabledFlag.Name) {
		utils.RegisterGraphQLService(stack, cfg.Node.GraphQLEndpoint(), cfg.Node.GraphQLCors, cfg.Node.GraphQLVirtualHosts, cfg.Node.HTTPTimeouts)
	}
	// Add the SimpleService Stats daemon if requested.
	if cfg.Ethstats.URL != "" {
		utils.RegisterEthStatsService(stack, cfg.Ethstats.URL)
	}
	utils.RegisterPermissionService(ctx, stack, mainCh)
	if ctx.GlobalBool(utils.RaftModeFlag.Name) {
		RegisterRaftService(stack, ctx, cfg, raftCh)
	}

	if ctx.GlobalBool(utils.MonitorModeFlag.Name) {
		RegisterMonitorService(stack, ctx, cfg)
	}

	// init hotstuff config and register service
	if ctx.GlobalBool(utils.HotstuffModeFlag.Name) && cfg.Eth.Hotstuff.Mine {
		RegisterHotstuffService(stack, ctx, &cfg.Eth)
	}
	return stack
}

func RegisterHotstuffService(stack *node.Node, ctx *cli.Context, cfg *eth.Config) {

	if err := stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		if cfg.Hotstuff.ServiceMaker == nil {
			return nil, errors.New("unknow Hotstuff service register")
		}
		return cfg.Hotstuff.ServiceMaker(cfg.Hotstuff.ChainReader), nil
	}); err != nil {
		utils.Fatalf("Failed to register the Hotstuff service: %v", err)
	}
}

func RegisterRaftService(stack *node.Node, ctx *cli.Context, cfg gethConfig, eth <-chan *eth.SimpleService) {
	var isFirstRaftNode bool
	if ctx.GlobalIsSet(utils.FirstRaftNodeFlag.Name) {
		isFirstRaftNode = ctx.GlobalBool(utils.FirstRaftNodeFlag.Name)
	}
	if err := stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		privkey := cfg.Node.NodeKey()
		strId := enode.PubkeyToIDV4(&privkey.PublicKey).String()
		peers := cfg.Node.StaticNodes()
		var myId uint16
		var joinExisting bool
		if !isFirstRaftNode {
			id := enode.PubkeyToIDV4(&privkey.PublicKey)
			raftId, err := raft.ReadGenRaftConfigJson(id[:], stack.InstanceDir())
			if err != nil {
				utils.Fatalf("ReadGenRaftConfigJson failed err:%v", err)
			} else {
				myId = raftId
			}
			if myId == 0 {
				utils.Fatalf("failed to find local enode ID (%v)", strId)
			}
			joinExisting = true
		} else if len(peers) == 0 {
			utils.Fatalf("Raft-based consensus requires either (1) an initial peers list (in static-nodes.json) including this enode hash (%v), or (2) the flag --raftjoinexisting RAFT_ID, where RAFT_ID has been issued by an existing cluster member calling `raft.addPeer(ENODE_ID)` with an enode ID containing this node's enode hash.", strId)
		} else {
			peerIds := make([]string, len(peers))

			for peerIdx, peer := range peers {
				if !peer.HasRaftPort() {
					utils.Fatalf("raftport querystring parameter not specified in static-node enode ID: %v. please check your static-nodes.json file.", peer.String())
				}
				peerId := peer.ID().String()
				peerIds[peerIdx] = peerId
				if peerId == strId {
					id := peer.ID()
					raftId, err := raft.ReadGenRaftConfigJson(id[:], stack.InstanceDir())
					if err != nil {
						utils.Fatalf("ReadGenRaftConfigJson failed err:%v", err)
					} else {
						myId = raftId
					}
				}
			}

			if myId == 0 {
				utils.Fatalf("failed to find local enode ID (%v) amongst peer IDs: %v", strId, peerIds)
			}
		}
		log.Info("raft id:", "myId", myId)
		log.Info("is join:", "joinExisting", joinExisting)
		return raftBackend.New(ctx, myId, uint16(cfg.Node.RaftPort), joinExisting, <-eth, peers, cfg.Node.DataDir)
	}); err != nil {
		utils.Fatalf("Failed to register the Raft service: %v", err)
	}

}
func RegisterMonitorService(stack *node.Node, ctx *cli.Context, cfg gethConfig) {
	if err := stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		fmt.Println("start monitor service")
		return monitor.New(fmt.Sprintf("%v", cfg.Node.MonitorPort)), nil
	}); err != nil {
		utils.Fatalf("Failed to register the Monitor service: %v", err)
	}
}

// dumpConfig is the dumpconfig command.
func dumpConfig(ctx *cli.Context) error {
	_, cfg := makeConfigNode(ctx)
	comment := ""

	if cfg.Eth.Genesis != nil {
		cfg.Eth.Genesis = nil
		comment += "# Note: this config doesn't contain the genesis block.\n\n"
	}

	out, err := tomlSettings.Marshal(&cfg)
	if err != nil {
		return err
	}

	dump := os.Stdout
	if ctx.NArg() > 0 {
		dump, err = os.OpenFile(ctx.Args().Get(0), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer dump.Close()
	}
	dump.WriteString(comment)
	dump.Write(out)

	return nil
}
