#!/bin/bash

accountCount=$1

if [ -z $accountCount ];then
  accountCount=10
fi

dir=$2

if [ -z $dir ];then
  dir="./tmp"
fi

password="123456"

cmd="./sipe"

for((i=0;i<$accountCount;i++))
do
	mkdir -p $dir
	echo "${password}">>"./password.txt"
	$cmd --data.dir=$dir  --password="./password.txt" account new
done