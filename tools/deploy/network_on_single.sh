#!/bin/bash

#################################本脚本适合于在一台服务器上进行区块链的体验####################################
#使用方法
# bash network-on-single.sh
#set -x

start=$(date +%s)

#注意！注意！注意！修改为本机的IP地址
host="192.168.4.157"

#一般不用修改
localIP="127.0.0.1"

rm -rf node*

#链的Id，可以自定义，只要是一个大于0的整数即可。
chainId=$(date '+%Y%m%d')

#等待时间
waitPeriod=3

#出块时间，以秒为单位
period=3

gasLimit=0x1cf1ab00

balance=0x84595161401484a000000

#三个账户，三个节点
allNodeCount=7

#一个节点一个账户
accountPasswords=("123456" "123456" "123456" "123456" "123456" "123456" "123456")

httpPort=6545

websocketPort=6546

p2pPort=30312

graphqlPort=6547

accounts=()

encodeNodes=()

cmd="./sipe"

if [ ! -e $cmd ];then
	echo "Make sure the file $cmd exists"
	exit 1
fi

chmod +x $cmd

if [ ! -e ./Permission.bin ];then
	echo "Make sure the file ./Permission.bin exists"
	exit 1
fi

chmod +x $cmd

# shellcheck disable=SC2004
for((i=0;i<${allNodeCount};i++))
do
	mkdir -p "node-$i/data"
	echo "${accountPasswords[$i]}">>./node-$i/password.txt
	content=$($cmd --data.dir=./node-$i/data --password=./node-$i/password.txt account new)
	echo "$content">>./node-$i/data/content.txt
	# shellcheck disable=SC2002
	account=$(cat ./node-$i/data/content.txt| grep "Public address of the key"|awk -F":" '{print $2}'| awk '{print $1}')
	accounts[$i]=$account
	echo " "
	echo "############ create account $i:$account ############ "
	echo " "
	rm -rf ./node-$i/data/content.txt
done

genesis="{\"config\":{\"chainId\":"

genesis="$genesis$chainId,"

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


genesis=$genesis$hotstuffpeer"]}},\"nonce\": \"0x0000000000000001\",\"timestamp\": \"0x611dd0cd\","

extraData="\"0x6800c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""

genesis=$genesis"\"extraData\":"

genesis=$genesis$extraData","

genesis=$genesis"\"gasLimit\": \"$gasLimit\","

end="\"difficulty\": \"0x1\",\"mixHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\"coinbase\": \"0x0000000000000000000000000000000000000000\","

end=$end"\"alloc\": {\"0000000000000000000000000000000000000000\": {\"balance\": \"0x1\"},"

#根据初始化，给管理员也是出块账户分配余额
# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do
	if [ $i -eq $((allNodeCount-1)) ] ;then
    end=$end"\"${accounts[$i]:2}\": {\"balance\": \"$balance\"}"
  else
    end=$end"\"${accounts[$i]:2}\": {\"balance\": \"$balance\"},"
  fi
done

end=$end"},"

end=$end"\"number\": \"0x0\",\"gasUsed\": \"0x0\",\"parentHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"}"

genesis=$genesis$end

echo "$genesis"

#每个目录下的都拷贝一个genesis.json文件
# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do
	echo "$genesis">>"./node-$i/genesis.json"
done

echo "############ genesis file generate success #################"

echo " "

sleep $waitPeriod

# shellcheck disable=SC2046
# shellcheck disable=SC2164
workdir="$(cd $(dirname "$0"); pwd)"



#初始化好每个节点目录
# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do

	httpPort=$((httpPort + 1000))

  websocketPort=$((websocketPort + 1000))

  p2pPort=$((p2pPort + 1000))

  graphqlPort=$((graphqlPort + 1000))

  pkill sipe

  #拷贝链的可执行程序
	cp -r "$workdir/sipe" "$workdir/node-$i"

	cp -r "$workdir/stop.sh" "$workdir/node-$i"

  #进入节点对应的目录
	# shellcheck disable=SC2164
	cd "$workdir/node-$i"


  #初始化链的数据目录
	$cmd --data.dir=./data --no.usb init genesis.json>>app.log 2>&1

  #将命令和启动参数都写入start.sh文件中
	# shellcheck disable=SC2129
	echo "#!/bin/bash">>./start.sh
	echo "export dataDir=./data">>./start.sh
	echo "export httpPort=$httpPort">>./start.sh
	echo "export p2pPort=$p2pPort">>./start.sh
	echo "export unlockAccount=${accounts[$i]}">>./start.sh
	echo "export password=./password.txt">>./start.sh
	echo "export websocketPort=$websocketPort">>./start.sh

	echo "nohup ./sipe \\">>./start.sh
  echo "--no.discover \\">>./start.sh
  echo "--no.usb \\">>./start.sh
	echo "--data.dir \$dataDir \\">>./start.sh
	echo "--gc.mode archive \\">>./start.sh
	echo "--allow-insecure-unlock \\">>./start.sh
	echo "--http \\">>./start.sh
	echo "--http.addr '0.0.0.0' \\">>./start.sh
	echo "--http.port \$httpPort \\">>./start.sh
	echo "--http.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start.sh
	echo "--http.cors.domain '*'  \\">>./start.sh
	echo "--port \$p2pPort \\">>./start.sh
	echo "--miner.gas.price 0 \\">>./start.sh
	echo "--unlock \$unlockAccount \\">>./start.sh
	echo "--password \$password \\">>./start.sh
	echo "--mine \\">>./start.sh
	echo "--miner.no.empty \\">>./start.sh
	echo "--miner.ether.base \$unlockAccount \\">>./start.sh
	echo "--sync.mode full \\">>./start.sh
	echo "--verbosity 4 \\">>./start.sh
	echo "--ws \\">>./start.sh
	echo "--ws.addr '0.0.0.0' \\">>./start.sh
	echo "--ws.port \$websocketPort \\">>./start.sh
	echo "--ws.api 'admin,miner,db,eth,net,web3,personal,debug,txpool,permission,raft,clique' \\">>./start.sh
	echo "--ws.origins '*'  \\">>./start.sh
	echo "--tx.pool.account.slots 10000  \\">>./start.sh
	echo "--tx.pool.global.slots  20000  \\">>./start.sh
	echo "--tx.pool.account.queue 10000 \\">>./start.sh
	echo "--tx.pool.global.queue 10240  \\">>./start.sh
	echo "--graphql \\">>./start.sh
	echo "--graphql.addr '0.0.0.0' \\">>./start.sh
	echo "--graphql.port $graphqlPort \\">>./start.sh
	echo "--graphql.cors.domain '*' \\">>./start.sh
	echo "--graphql.vhosts '*' \\">>./start.sh
	echo "--miner.gas.limit 238000000 \\">>./start.sh
	echo "--hotstuff \\">>./start.sh
	echo "--hotstuff.id $((i+1)) \\">>./start.sh
	echo " >> app.log 2>&1 &">>./start.sh


	#启动链服务
	bash ./start.sh
	sleep $waitPeriod
	if [ ! -e "./data/sipe.ipc" ];then
	        ls ./data
		      sleep $waitPeriod
  fi
	#获取节点的enode
	encodeNode=$($cmd attach data/sipe.ipc --exec "admin.nodeInfo.enode")

	# shellcheck disable=SC2154
	ip=${host}

	#将127.0.0.1替换为具体的ip地址
	remote=${encodeNode//$localIP/$ip}

	encodeNodes[(($i))]=$remote

done

echo " "

echo "############# node init success #############"

echo " "

pkill sipe

len=${#encodeNodes[*]}

staticNodes='['

for((i=0;i<len;i++))
do
  # shellcheck disable=SC2086
  if [ $i -eq $((len-1)) ] ;then
    staticNodes=$staticNodes${encodeNodes[$i]}
  else
    staticNodes=$staticNodes${encodeNodes[$i]}','
  fi
done

staticNodes=$staticNodes"]"

echo "############# static-nodes init success #############"

echo " "

# shellcheck disable=SC2164
cd "$workdir"

#每个目录下都有一个static-nodes.json文件
# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do
	echo "$staticNodes">>./node-$i/data/static-nodes.json
done

# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do
	# shellcheck disable=SC2164
	cd "$workdir"
  cd node-$i&&bash start.sh
done

echo "################ node start success ###################"

echo " "

# shellcheck disable=SC2164
cd "$workdir"

sleep $waitPeriod

#读取合约
code="0x$(<./Permission.bin)"

#取第一个节点
httpUrl="$workdir/node-0/data/sipe.ipc"

#部署合约
hash=$($cmd attach "${httpUrl}"  --exec "eth.sendTransaction({from:eth.accounts[0],data:\"${code}\"})")

echo "############# deploy contract hash:$hash #############"

echo " "

sleep $waitPeriod

#根据哈希获取合约地址

contractAddress=""

for ((i=1; i<=6; i++))
do

status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")

if [ "$status" = '"0x1"' ] ;then
	 echo " "
   echo "############# contract deploy success #############"
   echo " "
   contractAddress=$($cmd attach "${httpUrl}"  --exec "eth.getTransactionReceipt($hash).contractAddress")
   break
else
		sleep $waitPeriod
		echo "################ wait $waitPeriod seconds,please wait ################"
		echo " "
		blockNumber=$($cmd attach "${httpUrl}"  --exec "eth.blockNumber")
		echo "################ now blockchain number is:$blockNumber ################"
		echo " "
fi
done

if [[ $contractAddress == "" ]];then
	 echo "################ try 6 times,fail ################"
   exit 1
fi

# shellcheck disable=SC2164
cd "$workdir"

manageHashes=()

#初始的allNodeCount个节点都是管理员节点
# shellcheck disable=SC2004
for((i=0;i<$allNodeCount;i++))
do
	httpUrl="$workdir/node-$i/data/sipe.ipc"
	#必须给节点设置好合约地址，否则调用permission的接口各种method handler crashed
	 result=$($cmd attach "${httpUrl}"  --exec "permission.setPermissionContractAddress($contractAddress)")
	 if [ "$result" != "true" ];then
	 	   echo "$result"
	 	   exit 1
	 else
	 	   echo "node-$i setPermissionContractAddress $result"
	 	   echo " "
	 fi
   hash=$($cmd attach "${httpUrl}"  --exec "permission.setAdminNode(${encodeNodes[$i]},\"node-$i\",\"${accounts[$i]}\",eth.accounts[0])")
   if [[ $hash == \"0x* ]];then
   	  manageHashes[$i]=$hash
   else
   	  echo "setAdminNode result:$hash"
   	  echo " "
   fi
done
# shellcheck disable=SC2053
if [[ ${#manageHashes[*]} != $allNodeCount ]];then
	 echo "################ Not all the setAdminNode success ################"
	 echo " "
	 exit 1
fi


sleep $waitPeriod

#检测设置管理员节点是否全部成功，必须保证全部成功再进行下一步
for((i=0;i<${#manageHashes[*]};i++))
do
	httpUrl="$workdir/node-$i/data/sipe.ipc"
	hash=${manageHashes[$i]}
  status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
  if [ "$status" = '"0x1"' ] ;then
  	 echo "################ hash:$hash:success ################"
  	 echo " "
  else
  	#try again
  	echo "################ setAdminNode check again ################"
  	echo " "
  	sleep $waitPeriod
  	blockNumber=$($cmd attach "${httpUrl}"  --exec "eth.blockNumber")

		echo " "

		echo "################ now blockchain number is:$blockNumber ################"

		echo " "
  	status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
    if [ "$status" = '"0x1"' ] ;then
    	 echo "################ hash:$hash:success ################"
    	 echo " "
    	 break
    else
    	echo "################ hash:$hash:$status ################"
    	echo " "
    	exit 1
    fi
  fi
done

httpUrl="$workdir/node-0/data/sipe.ipc"

#结束网络的初始化
hash=$($cmd attach "${httpUrl}"  --exec "permission.initFinish(eth.accounts[0])")

sleep $waitPeriod

for ((i=1; i<=3; i++))
do

status=$($cmd attach "${httpUrl}"  --exec "var receipt=eth.getTransactionReceipt($hash);if(receipt!=null){receipt.status}")
if [ "$status" = '"0x1"' ] ;then

	echo "################ hash:$hash ################"

	echo " "

	echo "################ chain network init success ################"

	echo " "

	break

else
	echo "################ initFinish check again ################"
	echo " "
	sleep $waitPeriod
	blockNumber=$($cmd attach "${httpUrl}"  --exec "eth.blockNumber")
	echo " "
	echo "################ now blockchain number is:$blockNumber ################"
	echo " "
fi
done

# shellcheck disable=SC2009
ps aux|grep sipe

blockNumber=$($cmd attach "${httpUrl}"  --exec "eth.blockNumber")

echo " "

echo "################ now blockchain number is:$blockNumber ################"

echo " "

end=$(date +%s)

delta=$((end-start))

echo " "

echo "################ costs $delta seconds ################"

echo " "

#set +x