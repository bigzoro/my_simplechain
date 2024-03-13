##### 1s POA genesis.json

- init count= 0xffd79941b7085805f48ded97298694c6bb950e2c
```json
{
  "config": {
    "chainId": 110,
    "homesteadBlock": 1,
    "eip150Block": 2,
    "eip150Hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "eip155Block": 3,
    "eip158Block": 3,
    "byzantiumBlock": 4,
    "constantinopleBlock": 5,
    "clique": {
      "period":1, 
      "epoch": 30000
    }
  },
  "nonce": "0x0",
  "timestamp": "0x5d8993f8",
  "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000ffd79941b7085805f48ded97298694c6bb950e2c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "gasLimit": "0x7a1200",
  "difficulty": "0x1",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {
    "ffd79941b7085805f48ded97298694c6bb950e2c": {
      "balance": "0x200000000000000000000000000000000000000000000000000000000000000"
    }
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}

```

##### 导入0xffd79941b7085805f48ded97298694c6bb950e2c私钥

```bash
mkdir data
echo 04c070620a899a470a669fdbe0c6e1b663fd5bc953d9411eb36faa382005b3ad > privkey
echo 111111 > password
./bin/sipe account import ./privkey --password ./password --datadir ./data

```
##### sipe

- 初始化genesis block
```bash
sipe init ./poa.json --datadir data/
```

- 启动sipe
```bash
sipe --cache 1024 --datadir ./data --nodekey \
./nodekey --rpc --rpcvhosts "*"  --rpcaddr 0.0.0.0 \
--rpcport 8545 --rpccorsdomain "*" --rpcapi "db,eth,net,web3,personal,debug" \
--ws --wsorigins "*" --wsaddr 0.0.0.0 --wsport 8546 --wsapi "db,eth,net,web3,personal,debug" \
--unlock 0xffd79941b7085805f48ded97298694c6bb950e2c --password <(echo 111111)  \
--txpool.globalslots=51200 --verbosity 2  --gasprice 0 --miner.recommit=200000s  \
--miner.gaslimit=540000000
```

- 设置gc,开始挖矿
```bash
sipe attach data/sipe.ipc

> debug.setGCPercent(200)
100
> miner.start()
```


##### dummytx
带有20字节address+64字节随机值（模拟hash值）的转账交易, 
有7个向0xffd79941b7085805f48ded97298694c6bb950e2c转账的账户可选,
如果账户没足够的sipc, 会从0xffd79941b7085805f48ded97298694c6bb950e2c转出10000sipc给该账户

```bash
$ ./bin/dummytx -h
  Usage of ./bin/dummytx:
    -accounts int
      	the number of sender (default 4)
    -monitor
      	enable monitor txs in block
    -url string
      	websocket url (default "ws://127.0.0.1:8546")

```


```bash
$ ./bin/dummytx -accounts=3 --monitor
  2020/01/15 11:48:33 main.go:20: select 3 accounts
  2020/01/15 11:48:33 dummytx.go:74: sender:0 0xE60D800A6204cC85F90D18b278Bf1C6b74bbe0a8
  2020/01/15 11:48:33 dummytx.go:74: sender:1 0xCb385dCeA24c7Ce409378711430315E5530256bb
  2020/01/15 11:48:33 dummytx.go:74: sender:2 0x739603cA329A679C376FB185d20e7EbBd165EeA9
  2020/01/15 11:48:33 dummytx.go:133: waiting 5 seconds for claim funds txs finalize to block...
  2020/01/15 11:48:38 main.go:29: start monitor txs in blockChain
  2020/01/15 11:48:39 dummytx.go:250: block Number: 872, txCount: 0
  2020/01/15 11:48:40 dummytx.go:250: block Number: 873, txCount: 16280
  2020/01/15 11:48:41 dummytx.go:250: block Number: 874, txCount: 12601
  2020/01/15 11:48:42 dummytx.go:250: block Number: 875, txCount: 14500
  2020/01/15 11:48:43 dummytx.go:250: block Number: 876, txCount: 15170
  2020/01/15 11:48:44 dummytx.go:250: block Number: 877, txCount: 14764
  2020/01/15 11:48:45 dummytx.go:250: block Number: 878, txCount: 14473
  2020/01/15 11:48:46 dummytx.go:250: block Number: 879, txCount: 9659
  ^C2020/01/15 11:48:46 dummytx.go:198: warn: send tx: context canceled
  2020/01/15 11:48:46 dummytx.go:219: total finalize 97447 txs in 8.278950703 seconds, 11770.452983213036 txs/s
  2020/01/15 11:48:46 dummytx.go:156: sourceKey[1] return (total 38426 in 8.273616507 s, 4644.401872807277 txs/s)
  2020/01/15 11:48:46 dummytx.go:198: warn: send tx: context canceled
  2020/01/15 11:48:46 dummytx.go:156: sourceKey[0] return (total 38416 in 8.273467004 s, 4643.277114833103 txs/s)
  2020/01/15 11:48:46 dummytx.go:198: warn: send tx: context canceled
  2020/01/15 11:48:46 dummytx.go:156: sourceKey[2] return (total 38371 in 8.273688055 s, 4637.714130013814 txs/s)
  2020/01/15 11:48:47 main.go:42: txsCount=115213
  2020/01/15 11:48:47 main.go:43: dummy transaction exit
```