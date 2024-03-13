#!/bin/bash

#################################本脚本适合于在一台服务器上进行区块链的体验####################################
#使用方法
# bash network-on-single.sh

#注意！注意！注意！本机的IP地址

set -x

start=$(date +%s)

#服务器ip
host=192.168.124.5

#各个节点的http端口
ports=(7545 8545 9545)

#等待时间
waitPeriod=3

# shellcheck disable=SC2046
# shellcheck disable=SC2164
workdir=$(cd $(dirname "$0"); pwd)

cmd="./sipe"

if [ ! -e $cmd ];then
	echo "Make sure the file $cmd exists"
	exit 1
fi

if [ ! -e ./Permission.bin ];then
	echo "Make sure the file ./Permission.bin exists"
	exit 1
fi

chmod +x $cmd

#读取合约
code="0x$(<./Permission.bin)"

#节点连接
httpUrl="http://${host}:${ports[0]}"

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

#合约部署完毕

# shellcheck disable=SC2164
cd "$workdir"

manageHashes=()

#初始的ALL_NODE_COUNT个节点都是管理员节点
for((i=0;i<${#ports[*]};i++))
do
	httpUrl="http://${host}:${ports[$i]}"
	#必须给节点设置好合约地址，否则调用permission的接口各种method handler crashed
	 result=$($cmd attach "${httpUrl}"  --exec "permission.setPermissionContractAddress($contractAddress)")
	 if [ "$result" != "true" ];then
	 	   echo "$result"
	 	   exit 1
	 else
	 	   echo "node-$i setPermissionContractAddress $result"
	 	   echo " "
	 fi
   hash=$($cmd attach "${httpUrl}"  --exec "permission.setAdminNode(admin.nodeInfo.enode,\"node-$i\",eth.accounts[0],eth.accounts[0])")
   if [[ $hash == \"0x* ]];then
   	  manageHashes[$i]=$hash
   else
   	  echo "setAdminNode result:$hash"
   	  echo " "
   fi
done

# shellcheck disable=SC2053
if [[ ${#manageHashes[*]} != ${#ports[*]} ]];then
	 echo "################ Not all the setAdminNode success ################"
	 echo " "
	 exit 1
fi


sleep $waitPeriod

#检测设置管理员节点是否全部成功，必须保证全部成功再进行下一步
for((i=0;i<${#manageHashes[*]};i++))
do
	httpUrl="http://${host}:${ports[0]}"
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

httpUrl="http://${host}:${ports[0]}"

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

set +x