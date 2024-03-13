#!/bin/bash
if [ ! -e ./param_config.sh  ];then
	echo "Make sure the file ./param_config.sh exists"
	exit 1
fi

source ./param_config.sh

# shellcheck disable=SC2154
for((i=0;i<${#allNodeHosts[*]};i++))
do
   echo "${allNodeHosts[$i]}:"
	# shellcheck disable=SC2086
	ssh "${user}@${allNodeHosts[$i]}" "ps aux|grep sipe"
	echo " "
	echo " "
done

