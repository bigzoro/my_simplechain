#!/bin/sh

if [ ! -e /var/simplechain/production/sipe/sipe ];then
    sipe --datadir=/var/simplechain/production/sipe \
    --keystore /var/simplechain/sipe/keystore \
    --nousb init /var/simplechain/sipe/genesis.json
    sleep 1
fi
sipe --datadir /var/simplechain/production/sipe \
--allow-insecure-unlock \
--cache 1024 \
--gcmode archive \
--rpc \
--rpcvhosts "*" \
--rpcaddr "0.0.0.0" \
--rpcapi "admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique" \
--ws \
--rpc.tls.enable \
--wsorigins "*" \
--wsaddr "0.0.0.0" \
--wsapi "admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique" \
--keystore /var/simplechain/sipe/keystore \
--nousb \
--tlsenable \
--usercrtCN $1 \
--unlock 0 \
--password /var/simplechain/sipe/keystore/passwd.txt \
--syncmode full \
--nodiscover \
--permissioned \
--verbosity 1 \
--miner.gasprice 1 \
--mine \
--etherbase 0 \
--miner.noempty