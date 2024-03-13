#!/bin/bash

#要连接的管道文件路径
filePath="http://192.168.4.35:5545"

command="./sipe"

#常规文件
if [ ! -f $command ];then
   echo "$command not exists"
   exit 1
fi

start=$1

if [ -z $1 ];then
  start=1
fi

end=$2

if [ -z $2 ];then
  end=100
fi

blockNumber=$($command attach $filePath --exec="eth.blockNumber")

if [ $end -gt $blockNumber ];then
  end=$blockNumber
fi

first=0

last=0

txs=0

for((i=start;i<=end;i++))
do
   timestamp=$($command attach $filePath --exec="eth.getBlock($i).timestamp")
   if [ $i -eq $start ];then
     first=$timestamp
   fi
   txSize=$($command attach $filePath --exec="eth.getBlock($i).transactions.length")
   txs=$((txs+txSize))
   if [ $i -eq $end ];then
        last=$timestamp
   fi
   dateTime=$(date -d @"${timestamp}" '+%Y-%m-%d %H:%M:%S')
   echo "dateTime ${dateTime} block $i has $txSize transactions"
done

#必须四则运算的符号前后必须有空格
delta=`expr $last - $first`

#必须四则运算的符号前后必须有空格
tps=`expr $txs / $delta`


blocks=`expr $end - $start`


echo "blocks=$blocks,txs=$txs; last=$last; first=$first;tps=$tps;delta=$delta seconds"

