#!/bin/bash

if [ ! -e ./param_config.sh  ];then
	echo "Make sure the file ./param_config.sh exists"
	exit 1
fi
source ./param_config.sh
# shellcheck disable=SC2004
for((i=0;i<${#allNodeHosts[*]};i++))
do
	# shellcheck disable=SC2029
	ssh "${user}@${allNodeHosts[$i]}" "cd ${baseDir}/$projectDir/node-$i&&bash stop.sh"
done

bash check_sipe.sh