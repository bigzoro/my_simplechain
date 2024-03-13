#!/bin/bash

#本脚本在节点不启动CA的情况下使用
#本脚本部署合约并设置管理员节点和完成联盟的初始化
#本脚本不具备添加普通节点的功能

start=$(date +%s)

if [ ! -e ./param_config.sh  ];then
	echo "Make sure the file ./host_config.sh exists"
	exit 1
fi
source ./param_config.sh

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
#等待时间
waitPeriod=3

# shellcheck disable=SC2154
allNodeCount=${#allNodeHosts[*]}

accountCount=${#accountPasswords[*]}

# shellcheck disable=SC2086
# shellcheck disable=SC2154
if [ $initNodeCount -gt $allNodeCount ];then
	echo "The number of initial nodes is illegal. "
	echo "The number of initial nodes must be less than or equal to the total number of nodes"
	exit 1
fi

#一个节点一个账户，所以allNodeHosts的个数和accountPasswords个数必须一致
# shellcheck disable=SC2086
if [ $allNodeCount != $accountCount ];then
	 echo "all node hosts must equal account password"
	 exit 1
fi

#先确认，各个节点已经连接完成
expected=$((allNodeCount-1))

for((i=0;i<${#allNodeHosts[*]};i++))
do
	 # shellcheck disable=SC2027
	 # shellcheck disable=SC2154
	 httpUrl="http://"${allNodeHosts[$i]}":$httpPort"

	 peerCount=$(${cmd} attach "${httpUrl}"  --exec "admin.peers.length")

	 echo "节点 ${allNodeHosts[$i]} 连接数为:$peerCount"
	  
	 # shellcheck disable=SC2086
	 if [ $peerCount != $expected ];then
	 	  i=0
	 	  sleep $waitPeriod
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

sleep $waitPeriod

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
   sleep $waitPeriod
fi
done

if [[ $contractAddress == "" ]];then
	 echo "try 3 times,fail"
   exit 1
fi

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
   hash=$($cmd attach "${httpUrl}"  --exec "permission.setAdminNode(admin.nodeInfo.enode,\"${nodeNames[$i]}\",eth.accounts[0],eth.accounts[0])")
   if [[ $hash == \"0x* ]];then
   	  echo "hash:$hash;"
   	  manageHashes[$i]=$hash
   else
      echo  "result:$hash"
      echo  "httpUrl:${httpUrl}"
   	fi
done
# shellcheck disable=SC2053
if [[ ${#manageHashes[*]} != $initNodeCount ]];then
	 echo "Not all the setAdminNode success,want $initNodeCount ,got ${#manageHashes[*]}"
	 exit 1
fi

sleep $waitPeriod

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
  	sleep $waitPeriod
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

sleep $waitPeriod

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
	sleep $waitPeriod
fi
done

result=$($cmd attach "${httpUrl}"  --exec "permission.isNetworkInitFinished()")

echo "IsNetworkInitFinished:$result"

end=$(date +%s)

delta=$((end-start))

echo "costs $delta seconds."

