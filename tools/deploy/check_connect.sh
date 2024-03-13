#!/bin/bash

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

# shellcheck disable=SC2154
for((i=0;i<${#allNodeHosts[*]};i++))
do
	 # shellcheck disable=SC2027
	 httpUrl="http://"${allNodeHosts[$i]}":$httpPort"
	 echo -n "节点 ${allNodeHosts[$i]} 连接数为:"
	 ${cmd} attach "${httpUrl}"  --exec "admin.peers.length"
done

