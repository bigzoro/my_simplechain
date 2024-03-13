#!/bin/bash

#set -x

start=$(date +%s)

rm -rf node*

if [ ! -e ./param_config.sh  ];then
        echo "Make sure the file ./param_config.sh exists"
        exit 1
fi
source ./param_config.sh

cmd="./sipe"

if [ ! -f $cmd ];then
        echo "Make sure the file $cmd exists"
        exit 1
fi

chmod +x $cmd

if [ ! -f ./Permission.bin ];then
        echo "Make sure the file ./Permission.bin exists"
        exit 1
fi

# shellcheck disable=SC2154
allNodeCount=7

# shellcheck disable=SC2154
accountCount=${#accountPasswords[*]}

# shellcheck disable=SC2086
# shellcheck disable=SC2154
if [ $initNodeCount -gt $allNodeCount ];then
        echo "The number of initial nodes is illegal. "
        echo "The number of initial nodes must be less than or equal to the total number of nodes"
        exit 1
fi

#一个节点一个账户，所以allNodeHosts的个数和ACCOUNT_PASSWORDS个数必须一致
# shellcheck disable=SC2086
if [ $allNodeCount != $accountCount ];then
         echo "all node hosts must equal account password"
         exit 1
fi
 for((i=0;i<allNodeCount;i++))
 do
   # shellcheck disable=SC2154
   getConnection "${user}"      "${allNodeHosts[$i]}"
 done

echo "host check success"

##同步时间
## shellcheck disable=SC2004
#for((i=0;i<${allNodeCount};i++))
#do
#       scp  ./check-system.sh "${user}@${allNodeHosts[$i]}:~/check-system.sh"
#       ssh  "${user}@${allNodeHosts[$i]}" "bash ~/check-system.sh"
#done
#
#echo "host time sync  success"
#
## shellcheck disable=SC2004
#for((i=0;i<$allNodeCount;i++))
#do
#       echo "host:${allNodeHosts[$i]}"
#       ssh  "${user}@${allNodeHosts[$i]}" "date"
#done
#echo "host time compare......"

accounts=()

encodeNodes=()

# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
        mkdir -p "node-$i/data"
        echo "${accountPasswords[$i]}">>"./node-$i/password.txt"
        content=$($cmd --data.dir="./node-$i/data"  --password="./node-$i/password.txt" account new)
        echo "$content">>"./node-$i/data/content.txt"
        temp="./node-$i/data/content.txt"
        # shellcheck disable=SC2002
        account=$(cat ${temp}| grep "Public address of the key"|awk -F":" '{print $2}'| awk '{print $1}')
        accounts[$i]=$account
        echo "$i account:$account"
        rm -rf "./node-$i/data/content.txt"
done


genesis="{\"config\":{\"chainId\":"

# shellcheck disable=SC2154
genesis="$genesis$chainId,"

# shellcheck disable=SC2154
genesis=$genesis"\"singularityBlock\": 0,\"hotstuff\": {\"view\": 0,\"council\": "

hotstuffpeer='['

for((i=0;i<${allNodeCount};i++))
do
  peerInfo=$($cmd --data.dir=./node-$i/data genbls12sec)
  # shellcheck disable=SC2086
  if [ $i -eq $((allNodeCount-1)) ] ;then
    hotstuffpeer=$hotstuffpeer"{\"id\":$((i+1)),\"publicKey\":\"0x$peerInfo\"}"
  else
    hotstuffpeer=$hotstuffpeer"{\"id\":$((i+1)),\"publicKey\":\"0x$peerInfo\"},"
  fi
done

genesis=$genesis$hotstuffpeer"]}}, \"nonce\": \"0x0100000000000000\",\"timestamp\": \"0x611dd0cd\","

extraData="\"0xc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""

genesis=$genesis"\"extraData\":"

genesis=$genesis$extraData","

# shellcheck disable=SC2154
genesis=$genesis"\"gasLimit\": \"$gasLimit\","

end="\"difficulty\": \"0x1\",\"mixHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\"coinbase\": \"0x0000000000000000000000000000000000000000\","

end=$end"\"alloc\": {\"0000000000000000000000000000000000000000\": {\"balance\": \"0x1\"},"

#根据初始化，给管理员也是出块账户分配余额
# shellcheck disable=SC2004
for((i=0;i<${initNodeCount};i++))
do
        # shellcheck disable=SC2086
        if [ $i -eq $((initNodeCount-1)) ] ;then
    # shellcheck disable=SC2154
    end=$end"\"${accounts[$i]:2}\": {\"balance\": \"$balance\"}"
  else
    end=$end"\"${accounts[$i]:2}\": {\"balance\": \"$balance\"},"
  fi
done

end=$end"},"

end=$end"\"number\": \"0x0\",\"gasUsed\": \"0x0\",\"parentHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"}"

genesis=$genesis$end

#每个目录下的都拷贝一个genesis.json文件
# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
        echo "$genesis">>"./node-$i/genesis.json"
done

# shellcheck disable=SC2046
# shellcheck disable=SC2164
workdir="$(cd $(dirname $0); pwd)"

localIP="127.0.0.1"

#初始化好每个节点目录
# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
  # pkill sipe

  #拷贝链的可执行程序
        cp  "$workdir/sipe" "$workdir/node-$i"
        cp  "$workdir/stop.sh" "$workdir/node-$i"
        cp  "$workdir/transaction_stat.sh" "$workdir/node-$i"

  #进入节点对应的目录
        # shellcheck disable=SC2164
        cd "$workdir/node-$i"

  #初始化链的数据目录
        $cmd --data.dir=./data --no.usb init genesis.json

  #将命令和启动参数都写入start.sh文件中
        # shellcheck disable=SC2129
        echo "#!/bin/bash">>./start.sh
        echo "export dataDir=./data">>./start.sh
        # shellcheck disable=SC2154
        echo "export httpPort=$httpPort">>./start.sh
        # shellcheck disable=SC2154
        echo "export p2pPort=$p2pPort">>./start.sh
        echo "export unlockAccount=${accounts[$i]}">>./start.sh
        echo "export password=./password.txt">>./start.sh
        # shellcheck disable=SC2154
        echo "export WsPort=$websocketPort">>./start.sh
        echo "nohup $cmd \\">>./start.sh
  echo "--no.discover \\">>./start.sh
  echo "--no.usb \\">>./start.sh
        echo "--data.dir \$dataDir \\">>./start.sh
#       echo "--gc.mode archive \\">>./start.sh
        echo "--allow-insecure-unlock \\">>./start.sh
        echo "--http \\">>./start.sh
        echo "--http.addr '0.0.0.0' \\">>./start.sh
        echo "--http.port \$httpPort \\">>./start.sh
        echo "--http.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start.sh
        echo "--http.cors.domain '*'  \\">>./start.sh
        echo "--port \$p2pPort \\">>./start.sh
        echo "--tx.pool.global.slots 10000 \\">>./start.sh
        echo "--mine \\">>./start.sh
        echo "--miner.ether.base \$unlockAccount \\">>./start.sh
        echo "--miner.gas.price 0 \\">>./start.sh
        # shellcheck disable=SC2154
        echo "--miner.gas.limit $gasLimitDecimal \\">>./start.sh
        echo "--unlock \$unlockAccount \\">>./start.sh
        echo "--password \$password \\">>./start.sh
        echo "--ws \\">>./start.sh
        echo "--ws.addr '0.0.0.0' \\">>./start.sh
        echo "--ws.port \$WsPort \\">>./start.sh
        echo "--ws.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start.sh
        echo "--ws.origins '*'  \\">>./start.sh
        echo "--graphql \\">>./start.sh
        echo "--graphql.addr '0.0.0.0'  \\">>./start.sh
        # shellcheck disable=SC2154
        echo "--graphql.port  $graphqlPort \\">>./start.sh
        echo "--graphql.cors.domain '*'  \\">>./start.sh
        echo "--graphql.vhosts '*'  \\">>./start.sh
        echo "--miner.no.empty \\">>./start.sh
        echo "--miner.recommit='15s' \\">>./start.sh
        echo "--sync.mode full \\">>./start.sh
        echo "--verbosity 4 \\">>./start.sh
        echo "--permission \\">>./start.sh
        echo "--hotstuff \\">>./start.sh
        echo " >> app.log 2>&1 &">>./start.sh

        # shellcheck disable=SC2129
        echo "#!/bin/bash">>./start-with-ca.sh
        echo "export dataDir=./data">>./start-with-ca.sh
        echo "export httpPort=$httpPort">>./start-with-ca.sh
        echo "export p2pPort=$p2pPort">>./start-with-ca.sh
        echo "export unlockAccount=${accounts[$i]}">>./start-with-ca.sh
        echo "export password=./password.txt">>./start-with-ca.sh
        echo "export websocketPort=$websocketPort">>./start-with-ca.sh
        echo "nohup $cmd \\">>./start-with-ca.sh
  echo "--no.discover \\">>./start-with-ca.sh
  echo "--no.usb \\">>./start-with-ca.sh
        echo "--data.dir \$dataDir \\">>./start-with-ca.sh
        echo "--gc.mode archive \\">>./start-with-ca.sh
        echo "--allow-insecure-unlock \\">>./start-with-ca.sh
        echo "--http \\">>./start-with-ca.sh
        echo "--http.addr '0.0.0.0' \\">>./start-with-ca.sh
        echo "--http.port \$httpPort \\">>./start-with-ca.sh
        echo "--http.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start-with-ca.sh
        echo "--http.cors.domain '*'  \\">>./start-with-ca.sh
        echo "--port \$p2pPort \\">>./start-with-ca.sh
        echo "--tx.pool.global.slots 10000 \\">>./start-with-ca.sh
        echo "--mine \\">>./start-with-ca.sh
        echo "--miner.no.empty \\">>./start.sh
        echo "--miner.ether.base \$unlockAccount \\">>./start-with-ca.sh
        echo "--miner.gas.price 0 \\">>./start-with-ca.sh
        echo "--miner.gas.limit $gasLimitDecimal \\">>./start-with-ca.sh
        echo "--unlock \$unlockAccount \\">>./start-with-ca.sh
        echo "--password \$password \\">>./start-with-ca.sh
        echo "--sync.mode full \\">>./start-with-ca.sh
        echo "--verbosity 4 \\">>./start-with-ca.sh
        echo "--ws \\">>./start-with-ca.sh
        echo "--ws.addr '0.0.0.0' \\">>./start-with-ca.sh
        echo "--ws.port \$websocketPort \\">>./start-with-ca.sh
        echo "--ws.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start-with-ca.sh
        echo "--ws.origins '*'  \\">>./start-with-ca.sh
        echo "--peer.tls.enable \\">>./start-with-ca.sh
  # shellcheck disable=SC2154
  echo "--peer.tls.dir ${baseDir}/$projectDir/node-$i/node-$i/peer/tls-msp \\">>./start-with-ca.sh
  echo "--api.tls.enable \\">>./start-with-ca.sh
  echo "--graphql \\">>./start-with-ca.sh
        echo "--graphql.addr '0.0.0.0'  \\">>./start-with-ca.sh
        echo "--graphql.port  8547 \\">>./start-with-ca.sh
        echo "--graphql.cors.domain '*'  \\">>./start-with-ca.sh
        echo "--graphql.vhosts '*'  \\">>./start-with-ca.sh
        echo "--permission \\">>./start-with-ca.sh
        echo "--hotstuff \\">>./start.sh
  echo " >> app.log 2>&1 &">>./start.sh

        #启动链服务
        bash ./start.sh
        # shellcheck disable=SC2154
        sleep "$waitPeriod"
        if [ ! -e "./data/sipe.ipc" ];then
            ls ./data
                  sleep 5
  fi
        #获取节点的enode
        encodeNode=$($cmd attach data/sipe.ipc --exec "admin.nodeInfo.enode")

        ip=${allNodeHosts[$i]}

        #将127.0.0.1替换为具体的ip地址
        remote=${encodeNode//$localIP/$ip}

        encodeNodes[(($i))]=$remote

        bash ./stop.sh

done

#pkill sipe

len=${#encodeNodes[*]}

staticNodes='['

for((i=0;i<len;i++))
do
  if [ $i -eq $((len-1)) ] ;then
    staticNodes=$staticNodes${encodeNodes[$i]}
  else
    staticNodes=$staticNodes${encodeNodes[$i]}','
  fi
done

staticNodes=$staticNodes"]"

echo "staticNodes:$staticNodes"

# shellcheck disable=SC2164
cd "$workdir"

#每个目录下都有一个static-nodes.json文件
# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
        echo "$staticNodes">>"./node-$i/data/static-nodes.json"
done

# 将文件夹拷贝到目标机器上，并启动区块链节点服务
# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
        # shellcheck disable=SC2029
  # ssh "${user}@${allNodeHosts[$i]}" "cd ${baseDir}/$projectDir/node-$i&&bash stop.sh"

        # shellcheck disable=SC2029
        ssh "${user}@${allNodeHosts[$i]}" "rm -rf ${baseDir}/$projectDir&&mkdir -p ${baseDir}/$projectDir"

        # shellcheck disable=SC2086
        scp -r node-$i "${user}@${allNodeHosts[$i]}:${baseDir}/$projectDir/node-$i"

        # shellcheck disable=SC2029
        ssh "${user}@${allNodeHosts[$i]}" "cd ${baseDir}/$projectDir/node-$i&&bash start.sh"
done

sleep "$waitPeriod"

#先确认，各个节点已经连接完成
expected=$((allNodeCount - 1))

for((i=0;i<${#allNodeHosts[*]};i++))
do
         # shellcheck disable=SC2027
         httpUrl="http://"${allNodeHosts[$i]}":$httpPort"

         peerCount=$(${cmd} attach "${httpUrl}"  --exec "admin.peers.length")

         echo "节点 ${allNodeHosts[$i]} 连接数为:$peerCount"
          
         # shellcheck disable=SC2086
         if [ $peerCount != $expected ];then
                  i=0
                  sleep "$waitPeriod"
         fi
done

#读取合约
code="0x$(<./Permission.bin)"

#取第一个节点
# shellcheck disable=SC2027
httpUrl="http://"${allNodeHosts[0]}":$httpPort"

#部署合约
hash=$($cmd attach "${httpUrl}"  --exec "eth.sendTransaction({from:eth.accounts[0],data:\"${code}\"})")

echo "deploy contract hash:$hash"

sleep "$waitPeriod"

#根据哈希获取合约地址
for ((i=1; i<=3; i++))
do
contractAddress=""
status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
echo "status:$status"
if [ "$status" = '"0x1"' ] ;then
   echo "contract deploy success"
   contractAddress=$($cmd attach "${httpUrl}"  --exec "eth.getTransactionReceipt($hash).contractAddress")
   break
else
   sleep "$waitPeriod"
fi
done

if [[ $contractAddress == "" ]];then
         echo "try 3 times,fail"
   exit 1
fi

# shellcheck disable=SC2164
cd "$workdir"

manageHashes=()

#初始的initNodeCount个节点都是管理员节点
# shellcheck disable=SC2004
for((i=0;i<${initNodeCount};i++))
do
        # shellcheck disable=SC2027
        httpUrl="http://"${allNodeHosts[$i]}":$httpPort"
         result=$($cmd attach "${httpUrl}"  --exec "permission.setPermissionContractAddress($contractAddress)")
         if [ "$result" != "true" ];then
                   echo "$result"
                   exit 1
         fi
   # shellcheck disable=SC2154
   hash=$($cmd attach "${httpUrl}"  --exec "permission.setAdminNode(${encodeNodes[$i]},\"${nodeNames[$i]}\",\"${accounts[$i]}\",eth.accounts[0])")
   if [[ $hash == \"0x* ]];then
          echo "hash:$hash;"
          manageHashes[$i]=$hash
   else
      echo  "result:$hash"
      echo  "httpUrl:${httpUrl}"
        fi
done
# shellcheck disable=SC2053
if [[ ${#manageHashes[*]} != ${initNodeCount} ]];then
         echo "Not all the setAdminNode success,want ${initNodeCount} ,got ${#manageHashes[*]}"
         exit 1
fi

sleep "$waitPeriod"

#检测设置管理员节点是否全部成功，必须保证全部成功再进行下一步
for((i=0;i<${#manageHashes[*]};i++))
do
        # shellcheck disable=SC2027
        httpUrl="http://"${allNodeHosts[$i]}":$httpPort"
        hash=${manageHashes[$i]}
  status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
  if [ "$status" = '"0x1"' ] ;then
         echo "hash:$hash:success"
  else
        echo "hash:$hash:$status"
        echo "try getTransactionReceipt again"
        sleep "$waitPeriod"
        status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
    if [ "$status" = '"0x1"' ] ;then
         echo "hash:$hash:success"
    else
        echo "hash:$hash:$status"
        exit 1
    fi
  fi
done

# shellcheck disable=SC2027
httpUrl="http://"${allNodeHosts[0]}":$httpPort"

#结束网络的初始化
hash=$($cmd attach "${httpUrl}"  --exec "permission.initFinish(eth.accounts[0])")

sleep "$waitPeriod"

for((i=0;i<3;i++))
do
status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
if [ "$status" = '"0x1"' ] ;then
         echo "hash:$hash:success"
         echo "chain network init success"
         break
else
        echo "hash:$hash:$status"
        echo "try again"
        sleep "$waitPeriod"
fi
done

applyHashes=()
#用第一个节点为普通节点申请加入网络
# shellcheck disable=SC2004
for((i=$initNodeCount;i<$allNodeCount;i++))
do
        #必须给节点设置好合约地址，否则调用permission的接口各种method handler crashed
 hash=$($cmd attach "${httpUrl}"  --exec "permission.makeProposalForJoin(${encodeNodes[$i]},\"${nodeNames[$i]}\",\"${accounts[$i]}\",eth.accounts[0])")
  if [[ $hash == \"0x* ]];then
          echo "makeProposalForJoin hash:$hash;"
          applyHashes[(($i-$initNodeCount))]=$hash #要从0开始
  fi
done

#稍等一个块的时间
sleep "$waitPeriod"

for((i=0;i<${#applyHashes[*]};i++))
do
        hash=${applyHashes[$i]}
  status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
  if [ "$status" = '"0x1"' ] ;then
         echo "makeProposalForJoin hash:$hash:success"
  else
        echo "hash:$hash:$status"
        echo "try makeProposalForJoin getTransactionReceipt again"
        sleep "$waitPeriod"
        status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
    if [ "$status" = '"0x1"' ] ;then
         echo "makeProposalForJoin hash:$hash:success"
    else
        echo "hash:$hash:$status"
        exit 1
    fi
  fi
done



verifyHashes=()
# shellcheck disable=SC2004
for((i=0;i<${initNodeCount};i++))
do
         #连接管理员节点
         # shellcheck disable=SC2027
         httpUrl="http://"${allNodeHosts[$i]}":$httpPort"
         #管理员节点给每个节点投一票
         for((k=$initNodeCount;k<$allNodeCount;k++))
   do
      hash=$($cmd attach "${httpUrl}"  --exec "permission.acceptProposalForJoin(${encodeNodes[$k]},eth.accounts[0])")
      if [[ $hash == \"0x* ]];then
              echo "acceptProposalForJoin hash:$hash;"
              verifyHashes[${#verifyHashes[@]}]=$hash
      fi
   done
done

#稍等一个块的时间
sleep "$waitPeriod"

for((i=0;i<${#verifyHashes[*]};i++))
do
        hash=${verifyHashes[$i]}
  status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
  if [ "$status" = '"0x1"' ] ;then
         echo "acceptProposalForJoin hash:$hash:success"
  else
        echo "hash:$hash:$status"
        echo "try acceptProposalForJoin getTransactionReceipt again"
        sleep "$waitPeriod"
        status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
    if [ "$status" = '"0x1"' ] ;then
         echo "acceptProposalForJoin hash:$hash:success"
    else
        echo "hash:$hash:$status"
    fi
  fi
done


#为普通节点设置合约地址
# shellcheck disable=SC2004
for((i=$initNodeCount;i<$allNodeCount;i++))
do
 #必须给节点设置好合约地址，否则调用permission的接口各种method handler crashed
 # shellcheck disable=SC2027
 httpUrl="http://"${allNodeHosts[$i]}":$httpPort"
 $cmd attach "${httpUrl}"  --exec "permission.setPermissionContractAddress($contractAddress)"
done

# shellcheck disable=SC2027
httpUrl="http://"${allNodeHosts[0]}":$httpPort"

# shellcheck disable=SC2004
for((k=$initNodeCount;k<$allNodeCount;k++))
do
      hash=$($cmd attach "${httpUrl}"  --exec "permission.getNodeInfo(${encodeNodes[$k]},eth.accounts[0])")
          echo "nodeInfo:$hash;"Ï
done

end=$(date +%s)

delta=$((end-start))

echo "cost $delta seconds."

#set +x