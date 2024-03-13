#!/bin/bash

command="./sipe"

ipcPath="data/sipe.ipc"

if [ ! -e ${command} ];then
	echo "${command} file not exist"
	exit 1
fi

if [ ! -e ${ipcPath} ];then
	echo "${ipcPath} file not exist"
	exit 1
fi

num=$(${command} attach $ipcPath --exec="eth.blockNumber")

echo "current block number is ${num}"


start=$((num - 1))

end=$num

echo "end is $end"

if [ $# -ge 2 ];then
   start=$1
   end=$2
fi

sum=0

for ((i=$start; i <= $end; i++))
do
txs=$(${command} attach $ipcPath --exec="eth.getBlock($i).transactions.length")
echo "block $i has $txs transactions"
sum=$((${sum} + ${txs}))
done

echo $sum