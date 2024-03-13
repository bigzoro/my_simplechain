#/bin/bash

currentDir=$(cd $(dirname $0); pwd)

if [ ! -f $currentDir/build/bin/abigen ];then
   make all
fi

#使用0.6.0编译器进行编译
solc-select use  0.6.0

#首先生成在当前目录下，而后再手动拷贝到相应的目录下
$currentDir/build/bin/abigen  --sol=$currentDir/permission/contract/Permission.sol --pkg=permission  --out=./permission.go --lang=go

if [  -f ./permission.go ];then
   rm -rf $currentDir/permission/permission.go
   mv ./permission.go $currentDir/permission/
   echo "move success"
fi