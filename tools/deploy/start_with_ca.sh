#!/bin/bash

if [ ! -e ./param_config.sh  ];then
	echo "Make sure the file ./host_config.sh exists"
	exit 1
fi

source ./param_config.sh

# shellcheck disable=SC2154
for((i=0;i<${#allNodeHosts[*]};i++))
do
	# shellcheck disable=SC2029
	ssh "${user}@${allNodeHosts[$i]}" "cd ${baseDir}/${projectDir}/node-$i&&bash stop.sh&&bash start-with-ca.sh"
done
