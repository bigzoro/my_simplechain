// Copyright 2015 The go-simplechain Authors
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

// package web3ext contains geth specific web3.js extensions.
package web3ext

var Modules = map[string]string{
	"accounting": AccountingJs,
	"admin":      AdminJs,
	"chequebook": ChequebookJs,
	"clique":     CliqueJs,
	"ethash":     EthashJs,
	"debug":      DebugJs,
	"eth":        EthJs,
	"miner":      MinerJs,
	"net":        NetJs,
	"personal":   PersonalJs,
	"rpc":        RpcJs,
	"shh":        ShhJs,
	"swarmfs":    SwarmfsJs,
	"txpool":     TxpoolJs,
	"les":        LESJs,
	"permission": Permission_JS,
	"raft":       Raft_JS,
	"pbft":       PBFT_JS,
	"hotstuff":   HOTSTUFF_JS,
}

const HOTSTUFF_JS = `
web3._extend({
	property: 'hotstuff',
	methods: [
		new web3._extend.Method({
			name: 'add',
			call: 'hotstuff_add',
			params: 4,
		}),
		new web3._extend.Method({
			name: 'remove',
			call: 'hotstuff_remove',
			params: 3,
		}),
		new web3._extend.Method({
			name: 'proposeAdd',
			call: 'hotstuff_proposeAdd',
			params: 3,
		}),
		new web3._extend.Method({
			name: 'proposeRemove',
			call: 'hotstuff_proposeRemove',
			params: 2,
		}),
		new web3._extend.Method({
			name: 'aggregate',
			call: 'hotstuff_aggregate',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'getReplicaInfo',
			call: 'hotstuff_getReplicaInfo',
			params: 1,
		}),
	]
});
`

const PBFT_JS = `
web3._extend({
	property: 'pbft',
	methods:
	[
		new web3._extend.Method({
			name: 'getSnapshot',
			call: 'pbft_getSnapshot',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'getSnapshotAtHash',
			call: 'pbft_getSnapshotAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getValidators',
			call: 'pbft_getValidators',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'getValidatorsAtHash',
			call: 'pbft_getValidatorsAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'propose',
			call: 'pbft_propose',
			params: 2
		}),
		new web3._extend.Method({
			name: 'discard',
			call: 'pbft_discard',
			params: 1
		}),

		new web3._extend.Method({
			name: 'getSignersFromBlock',
			call: 'pbft_getSignersFromBlock',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputBlockNumberFormatter]
		}),
		new web3._extend.Method({
			name: 'getSignersFromBlockByHash',
			call: 'pbft_getSignersFromBlockByHash',
			params: 1
		}),
	],
	properties:
	[
		new web3._extend.Property({
			name: 'candidates',
			getter: 'pbft_candidates'
		}),
		new web3._extend.Property({
			name: 'nodeAddress',
			getter: 'pbft_nodeAddress'
		}),
	]
});
`

const Raft_JS = `web3._extend({
       property: 'raft',
       methods:
       [
       ],
       properties:
       [
               new web3._extend.Property({
                       name: 'role',
                       getter: 'raft_role'
               }),
			   new web3._extend.Method({
                      name: 'changeRole',
                      call: 'raft_changeRole',
                      params: 1
               }),
               new web3._extend.Method({
                      name: 'addPeer',
                      call: 'raft_addPeer',
                      params: 1
               }),
               new web3._extend.Method({
                      name: 'removePeer',
                      call: 'raft_removePeer',
                      params: 1
               }),
			   new web3._extend.Property({
                       name: 'getMaxRaftId',
                       getter: 'raft_getMaxRaftId'
               }),
               new web3._extend.Property({
                       name: 'leader',
                       getter: 'raft_leader'
               }),
               new web3._extend.Property({
                       name: 'cluster',
                       getter: 'raft_cluster'
               }),
       ]
})
`

const Permission_JS = `web3._extend({
	property: 'permission',
	methods: [
		new web3._extend.Method({
			name: 'addPeer',
			call: 'permission_addPeer',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'removePeer',
			call: 'permission_removePeer',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'setAdminNode',
			call: 'permission_setAdminNode',
			params: 4,
			inputFormatter: [null, null, web3._extend.formatters.inputAddressFormatter, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'initFinish',
			call: 'permission_initFinish',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'makeProposalForJoin',
			call: 'permission_makeProposalForJoin',
			params: 4,
			inputFormatter: [null, null, web3._extend.formatters.inputAddressFormatter, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'acceptProposalForJoin',
			call: 'permission_acceptProposalForJoin',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'rejectProposalForJoin',
			call: 'permission_rejectProposalForJoin',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'makeProposalForAdmin',
			call: 'permission_makeProposalForAdmin',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'acceptProposalForAdmin',
			call: 'permission_acceptProposalForAdmin',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'rejectProposalForAdmin',
			call: 'permission_rejectProposalForAdmin',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'makeProposalForCommon',
			call: 'permission_makeProposalForCommon',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'acceptProposalForCommon',
			call: 'permission_acceptProposalForCommon',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'rejectProposalForCommon',
			call: 'permission_rejectProposalForCommon',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'makeProposalForExit',
			call: 'permission_makeProposalForExit',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'acceptProposalForExit',
			call: 'permission_acceptProposalForExit',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'rejectProposalForExit',
			call: 'permission_rejectProposalForExit',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'isNetworkInitFinished',
			call: 'permission_isNetworkInitFinished',
			params: 0,
			inputFormatter: []
		}),
		new web3._extend.Method({
			name: 'updateNodeInfo',
			call: 'permission_updateNodeInfo',
			params: 3,
			inputFormatter: [null,null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'exit',
			call: 'permission_exit',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getNodeByRole',
			call: 'permission_getNodeByRole',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getNodeRole',
			call: 'permission_getNodeRole',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getNodeInfoByName',
			call: 'permission_getNodeInfoByName',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getStateMap',
			call: 'permission_getStateMap',
			params: 3,
			inputFormatter: [null, null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getNodeInfo',
			call: 'permission_getNodeInfo',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getAllStatingRecord',
			call: 'permission_getAllStatingRecord',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'isAdmin',
			call: 'permission_isAdmin',
			params: 2,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'setPermissionContractAddress',
			call: 'permission_setPermissionContractAddress',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getPermissionContractAddress',
			call: 'permission_getPermissionContractAddress',
			params: 0,
			inputFormatter: []
		}),
		new web3._extend.Method({
			name: 'setStoreContractAddress',
			call: 'permission_setStoreContractAddress',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getStoreContractAddress',
			call: 'permission_getStoreContractAddress',
			params: 0,
			inputFormatter: []
		}),
		new web3._extend.Method({
			name: 'storeContractAbi',
			call: 'permission_storeContractAbi',
			params: 4,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter,null,null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getContractAbi',
			call: 'permission_getContractAbi',
			params: 2,
			inputFormatter: [null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'updateNodeName',
			call: 'permission_updateNodeName',
			params: 3,
			inputFormatter: [null,null,web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'getAdminCount',
			call: 'permission_getAdminCount',
			params: 0,
			inputFormatter: []
		}), 
		new web3._extend.Method({
			name: 'nodeExists',
			call: 'permission_nodeExists',
			params: 1,
			inputFormatter: [null]
        }) 
	],
	properties:
    [
		  new web3._extend.Property({
				   name: 'retreive',
				   getter: 'permission_retreive'
		  }), 
    ]
});`

const ChequebookJs = `
web3._extend({
	property: 'chequebook',
	methods: [
		new web3._extend.Method({
			name: 'deposit',
			call: 'chequebook_deposit',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Property({
			name: 'balance',
			getter: 'chequebook_balance',
			outputFormatter: web3._extend.utils.toDecimal
		}),
		new web3._extend.Method({
			name: 'cash',
			call: 'chequebook_cash',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'issue',
			call: 'chequebook_issue',
			params: 2,
			inputFormatter: [null, null]
		}),
	]
});
`

const CliqueJs = `
web3._extend({
	property: 'clique',
	methods: [
		new web3._extend.Method({
			name: 'getSnapshot',
			call: 'clique_getSnapshot',
			params: 1,
			inputFormatter: [web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'getSnapshotAtHash',
			call: 'clique_getSnapshotAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getSigners',
			call: 'clique_getSigners',
			params: 1,
			inputFormatter: [web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'getSignersAtHash',
			call: 'clique_getSignersAtHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'propose',
			call: 'clique_propose',
			params: 2
		}),
		new web3._extend.Method({
			name: 'discard',
			call: 'clique_discard',
			params: 1
		}),
		new web3._extend.Method({
			name: 'status',
			call: 'clique_status',
			params: 0
		}),
	],
	properties: [
		new web3._extend.Property({
			name: 'proposals',
			getter: 'clique_proposals'
		}),
	]
});
`

const EthashJs = `
web3._extend({
	property: 'ethash',
	methods: [
		new web3._extend.Method({
			name: 'getWork',
			call: 'ethash_getWork',
			params: 0
		}),
		new web3._extend.Method({
			name: 'getHashrate',
			call: 'ethash_getHashrate',
			params: 0
		}),
		new web3._extend.Method({
			name: 'submitWork',
			call: 'ethash_submitWork',
			params: 3,
		}),
		new web3._extend.Method({
			name: 'submitHashRate',
			call: 'ethash_submitHashRate',
			params: 2,
		}),
	]
});
`

const AdminJs = `
web3._extend({
	property: 'admin',
	methods: [
		//new web3._extend.Method({
		//	name: 'addPeer',
		//	call: 'admin_addPeer',
		//	params: 1
		//}),
		//new web3._extend.Method({
		//	name: 'removePeer',
		//	call: 'admin_removePeer',
		//	params: 1
		//}),
		new web3._extend.Method({
			name: 'addTrustedPeer',
			call: 'admin_addTrustedPeer',
			params: 1
		}),
		new web3._extend.Method({
			name: 'removeTrustedPeer',
			call: 'admin_removeTrustedPeer',
			params: 1
		}),
		new web3._extend.Method({
			name: 'exportChain',
			call: 'admin_exportChain',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'importChain',
			call: 'admin_importChain',
			params: 1
		}),
		new web3._extend.Method({
			name: 'sleepBlocks',
			call: 'admin_sleepBlocks',
			params: 2
		}),
		new web3._extend.Method({
			name: 'startRPC',
			call: 'admin_startRPC',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'stopRPC',
			call: 'admin_stopRPC'
		}),
		new web3._extend.Method({
			name: 'startWS',
			call: 'admin_startWS',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new web3._extend.Method({
			name: 'stopWS',
			call: 'admin_stopWS'
		}),
	],
	properties: [
		new web3._extend.Property({
			name: 'nodeInfo',
			getter: 'admin_nodeInfo'
		}),
		new web3._extend.Property({
			name: 'peers',
			getter: 'admin_peers'
		}),
		new web3._extend.Property({
			name: 'datadir',
			getter: 'admin_datadir'
		}),
	]
});
`

const DebugJs = `
web3._extend({
	property: 'debug',
	methods: [
		new web3._extend.Method({
			name: 'accountRange',
			call: 'debug_accountRange',
			params: 2
		}),
		new web3._extend.Method({
			name: 'printBlock',
			call: 'debug_printBlock',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getBlockRlp',
			call: 'debug_getBlockRlp',
			params: 1
		}),
		new web3._extend.Method({
			name: 'testSignCliqueBlock',
			call: 'debug_testSignCliqueBlock',
			params: 2,
			inputFormatters: [web3._extend.formatters.inputAddressFormatter, null],
		}),
		new web3._extend.Method({
			name: 'setHead',
			call: 'debug_setHead',
			params: 1
		}),
		new web3._extend.Method({
			name: 'seedHash',
			call: 'debug_seedHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'dumpBlock',
			call: 'debug_dumpBlock',
			params: 1
		}),
		new web3._extend.Method({
			name: 'chaindbProperty',
			call: 'debug_chaindbProperty',
			params: 1,
			outputFormatter: console.log
		}),
		new web3._extend.Method({
			name: 'chaindbCompact',
			call: 'debug_chaindbCompact',
		}),
		new web3._extend.Method({
			name: 'verbosity',
			call: 'debug_verbosity',
			params: 1
		}),
		new web3._extend.Method({
			name: 'vmodule',
			call: 'debug_vmodule',
			params: 1
		}),
		new web3._extend.Method({
			name: 'backtraceAt',
			call: 'debug_backtraceAt',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'stacks',
			call: 'debug_stacks',
			params: 0,
			outputFormatter: console.log
		}),
		new web3._extend.Method({
			name: 'freeOSMemory',
			call: 'debug_freeOSMemory',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'setGCPercent',
			call: 'debug_setGCPercent',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'memStats',
			call: 'debug_memStats',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'gcStats',
			call: 'debug_gcStats',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'cpuProfile',
			call: 'debug_cpuProfile',
			params: 2
		}),
		new web3._extend.Method({
			name: 'startCPUProfile',
			call: 'debug_startCPUProfile',
			params: 1
		}),
		new web3._extend.Method({
			name: 'stopCPUProfile',
			call: 'debug_stopCPUProfile',
			params: 0
		}),
		new web3._extend.Method({
			name: 'goTrace',
			call: 'debug_goTrace',
			params: 2
		}),
		new web3._extend.Method({
			name: 'startGoTrace',
			call: 'debug_startGoTrace',
			params: 1
		}),
		new web3._extend.Method({
			name: 'stopGoTrace',
			call: 'debug_stopGoTrace',
			params: 0
		}),
		new web3._extend.Method({
			name: 'blockProfile',
			call: 'debug_blockProfile',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setBlockProfileRate',
			call: 'debug_setBlockProfileRate',
			params: 1
		}),
		new web3._extend.Method({
			name: 'writeBlockProfile',
			call: 'debug_writeBlockProfile',
			params: 1
		}),
		new web3._extend.Method({
			name: 'mutexProfile',
			call: 'debug_mutexProfile',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setMutexProfileFraction',
			call: 'debug_setMutexProfileFraction',
			params: 1
		}),
		new web3._extend.Method({
			name: 'writeMutexProfile',
			call: 'debug_writeMutexProfile',
			params: 1
		}),
		new web3._extend.Method({
			name: 'writeMemProfile',
			call: 'debug_writeMemProfile',
			params: 1
		}),
		new web3._extend.Method({
			name: 'traceBlock',
			call: 'debug_traceBlock',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'traceBlockFromFile',
			call: 'debug_traceBlockFromFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'traceBadBlock',
			call: 'debug_traceBadBlock',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'standardTraceBadBlockToFile',
			call: 'debug_standardTraceBadBlockToFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'standardTraceBlockToFile',
			call: 'debug_standardTraceBlockToFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'traceBlockByNumber',
			call: 'debug_traceBlockByNumber',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'traceBlockByHash',
			call: 'debug_traceBlockByHash',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'traceTransaction',
			call: 'debug_traceTransaction',
			params: 2,
			inputFormatter: [null, null]
		}),
		new web3._extend.Method({
			name: 'preimage',
			call: 'debug_preimage',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'getBadBlocks',
			call: 'debug_getBadBlocks',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'storageRangeAt',
			call: 'debug_storageRangeAt',
			params: 5,
		}),
		new web3._extend.Method({
			name: 'getModifiedAccountsByNumber',
			call: 'debug_getModifiedAccountsByNumber',
			params: 2,
			inputFormatter: [null, null],
		}),
		new web3._extend.Method({
			name: 'getModifiedAccountsByHash',
			call: 'debug_getModifiedAccountsByHash',
			params: 2,
			inputFormatter:[null, null],
		}),
		new web3._extend.Method({
			name: 'freezeClient',
			call: 'debug_freezeClient',
			params: 1,
		}),
	],
	properties: []
});
`

const EthJs = `
web3._extend({
	property: 'eth',
	methods: [
		new web3._extend.Method({
			name: 'chainId',
			call: 'eth_chainId',
			params: 0
		}),
		new web3._extend.Method({
			name: 'sign',
			call: 'eth_sign',
			params: 2,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter, null]
		}),
		new web3._extend.Method({
			name: 'resend',
			call: 'eth_resend',
			params: 3,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter, web3._extend.utils.fromDecimal, web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'signTransaction',
			call: 'eth_signTransaction',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'submitTransaction',
			call: 'eth_submitTransaction',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'fillTransaction',
			call: 'eth_fillTransaction',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter]
		}),
		new web3._extend.Method({
			name: 'getHeaderByNumber',
			call: 'eth_getHeaderByNumber',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getHeaderByHash',
			call: 'eth_getHeaderByHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getBlockByNumber',
			call: 'eth_getBlockByNumber',
			params: 2
		}),
		new web3._extend.Method({
			name: 'getBlockByHash',
			call: 'eth_getBlockByHash',
			params: 2
		}),
		new web3._extend.Method({
			name: 'getLatestBlockNumber',
			call: 'eth_getLatestBlockNumber',
			params: 0
		}),
		new web3._extend.Method({
			name: 'getRawTransaction',
			call: 'eth_getRawTransactionByHash',
			params: 1
		}),
		new web3._extend.Method({
			name: 'getRawTransactionFromBlock',
			call: function(args) {
				return (web3._extend.utils.isString(args[0]) && args[0].indexOf('0x') === 0) ? 'eth_getRawTransactionByBlockHashAndIndex' : 'eth_getRawTransactionByBlockNumberAndIndex';
			},
			params: 2,
			inputFormatter: [web3._extend.formatters.inputBlockNumberFormatter, web3._extend.utils.toHex]
		}),
		new web3._extend.Method({
			name: 'getProof',
			call: 'eth_getProof',
			params: 3,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter, null, web3._extend.formatters.inputBlockNumberFormatter]
		}),
	],
	properties: [
		new web3._extend.Property({
			name: 'pendingTransactions',
			getter: 'eth_pendingTransactions',
			outputFormatter: function(txs) {
				var formatted = [];
				for (var i = 0; i < txs.length; i++) {
					formatted.push(web3._extend.formatters.outputTransactionFormatter(txs[i]));
					formatted[i].blockHash = null;
				}
				return formatted;
			}
		}),
	]
});
`

const MinerJs = `
web3._extend({
	property: 'miner',
	methods: [
		new web3._extend.Method({
			name: 'start',
			call: 'miner_start',
			params: 1,
			inputFormatter: [null]
		}),
		new web3._extend.Method({
			name: 'stop',
			call: 'miner_stop'
		}),
		new web3._extend.Method({
			name: 'setEtherbase',
			call: 'miner_setEtherbase',
			params: 1,
			inputFormatter: [web3._extend.formatters.inputAddressFormatter]
		}),
		new web3._extend.Method({
			name: 'setExtra',
			call: 'miner_setExtra',
			params: 1
		}),
		new web3._extend.Method({
			name: 'setGasPrice',
			call: 'miner_setGasPrice',
			params: 1,
			inputFormatter: [web3._extend.utils.fromDecimal]
		}),
		new web3._extend.Method({
			name: 'setRecommitInterval',
			call: 'miner_setRecommitInterval',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'getHashrate',
			call: 'miner_getHashrate'
		}),
	],
	properties: []
});
`

const NetJs = `
web3._extend({
	property: 'net',
	methods: [],
	properties: [
		new web3._extend.Property({
			name: 'version',
			getter: 'net_version'
		}),
	]
});
`

const PersonalJs = `
web3._extend({
	property: 'personal',
	methods: [
		new web3._extend.Method({
			name: 'importRawKey',
			call: 'personal_importRawKey',
			params: 2
		}),
		new web3._extend.Method({
			name: 'sign',
			call: 'personal_sign',
			params: 3,
			inputFormatter: [null, web3._extend.formatters.inputAddressFormatter, null]
		}),
		new web3._extend.Method({
			name: 'ecRecover',
			call: 'personal_ecRecover',
			params: 2
		}),
		new web3._extend.Method({
			name: 'openWallet',
			call: 'personal_openWallet',
			params: 2
		}),
		new web3._extend.Method({
			name: 'deriveAccount',
			call: 'personal_deriveAccount',
			params: 3
		}),
		new web3._extend.Method({
			name: 'signTransaction',
			call: 'personal_signTransaction',
			params: 2,
			inputFormatter: [web3._extend.formatters.inputTransactionFormatter, null]
		}),
		new web3._extend.Method({
			name: 'unpair',
			call: 'personal_unpair',
			params: 2
		}),
		new web3._extend.Method({
			name: 'initializeWallet',
			call: 'personal_initializeWallet',
			params: 1
		})
	],
	properties: [
		new web3._extend.Property({
			name: 'listWallets',
			getter: 'personal_listWallets'
		}),
	]
})
`

const RpcJs = `
web3._extend({
	property: 'rpc',
	methods: [],
	properties: [
		new web3._extend.Property({
			name: 'modules',
			getter: 'rpc_modules'
		}),
	]
});
`

const ShhJs = `
web3._extend({
	property: 'shh',
	methods: [
	],
	properties:
	[
		new web3._extend.Property({
			name: 'version',
			getter: 'shh_version',
			outputFormatter: web3._extend.utils.toDecimal
		}),
		new web3._extend.Property({
			name: 'info',
			getter: 'shh_info'
		}),
	]
});
`

const SwarmfsJs = `
web3._extend({
	property: 'swarmfs',
	methods:
	[
		new web3._extend.Method({
			name: 'mount',
			call: 'swarmfs_mount',
			params: 2
		}),
		new web3._extend.Method({
			name: 'unmount',
			call: 'swarmfs_unmount',
			params: 1
		}),
		new web3._extend.Method({
			name: 'listmounts',
			call: 'swarmfs_listmounts',
			params: 0
		}),
	]
});
`

const TxpoolJs = `
web3._extend({
	property: 'txpool',
	methods: [],
	properties:
	[
		new web3._extend.Property({
			name: 'content',
			getter: 'txpool_content'
		}),
		new web3._extend.Property({
			name: 'inspect',
			getter: 'txpool_inspect'
		}),
		new web3._extend.Property({
			name: 'status',
			getter: 'txpool_status',
			outputFormatter: function(status) {
				status.pending = web3._extend.utils.toDecimal(status.pending);
				status.queued = web3._extend.utils.toDecimal(status.queued);
				return status;
			}
		}),
	]
});
`

const AccountingJs = `
web3._extend({
	property: 'accounting',
	methods: [
		new web3._extend.Property({
			name: 'balance',
			getter: 'account_balance'
		}),
		new web3._extend.Property({
			name: 'balanceCredit',
			getter: 'account_balanceCredit'
		}),
		new web3._extend.Property({
			name: 'balanceDebit',
			getter: 'account_balanceDebit'
		}),
		new web3._extend.Property({
			name: 'bytesCredit',
			getter: 'account_bytesCredit'
		}),
		new web3._extend.Property({
			name: 'bytesDebit',
			getter: 'account_bytesDebit'
		}),
		new web3._extend.Property({
			name: 'msgCredit',
			getter: 'account_msgCredit'
		}),
		new web3._extend.Property({
			name: 'msgDebit',
			getter: 'account_msgDebit'
		}),
		new web3._extend.Property({
			name: 'peerDrops',
			getter: 'account_peerDrops'
		}),
		new web3._extend.Property({
			name: 'selfDrops',
			getter: 'account_selfDrops'
		}),
	]
});
`

const LESJs = `
web3._extend({
	property: 'les',
	methods:
	[
		new web3._extend.Method({
			name: 'getCheckpoint',
			call: 'les_getCheckpoint',
			params: 1
		}),
		new web3._extend.Method({
			name: 'clientInfo',
			call: 'les_clientInfo',
			params: 1
		}),
		new web3._extend.Method({
			name: 'priorityClientInfo',
			call: 'les_priorityClientInfo',
			params: 3
		}),
		new web3._extend.Method({
			name: 'setClientParams',
			call: 'les_setClientParams',
			params: 2
		}),
		new web3._extend.Method({
			name: 'setDefaultParams',
			call: 'les_setDefaultParams',
			params: 1
		}),
		new web3._extend.Method({
			name: 'addBalance',
			call: 'les_addBalance',
			params: 3
		}),
	],
	properties:
	[
		new web3._extend.Property({
			name: 'latestCheckpoint',
			getter: 'les_latestCheckpoint'
		}),
		new web3._extend.Property({
			name: 'checkpointContractAddress',
			getter: 'les_getCheckpointContractAddress'
		}),
		new web3._extend.Property({
			name: 'serverInfo',
			getter: 'les_serverInfo'
		}),
	]
});
`
