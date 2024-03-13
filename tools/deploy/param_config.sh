#!/bin/bash

#服务器用户名
# shellcheck disable=SC2034
user="root"

#提供rpc服务的http端口,应用系统接入链时使用
# shellcheck disable=SC2034
httpPort=8545

#提供rpc服务的websocket端口,应用系统接入链时使用
# shellcheck disable=SC2034
websocketPort=8546

#区块链之间点对点通信使用的端口
# shellcheck disable=SC2034
p2pPort=30315

graphqlPort=8547

#部署链系统的相对目录
# shellcheck disable=SC2034
# shellcheck disable=SC2088
baseDir="/home/chain"

#项目目录名
# shellcheck disable=SC2034
projectDir="jinzong"

#初始所有的区块链节点
# shellcheck disable=SC2034
allNodeHosts=(192.168.4.34 192.168.4.35 192.168.4.36 192.168.4.37)

#一个节点一个账户，所以allNodeHosts的个数和accountPasswords个数必须一致
accountPasswords=("123456" "123456" "123456" "123456")


#定义初始节点数,将管理节点放在前面
initNodeCount=4

#节点名称
nodeNames=("中国工商银行" "杭州银行" "浙商银行" "银保监")

balance=0xffff84595161401484a000000

#等待时间
waitPeriod=3

#出块时间，以秒为单位
period=3

gasLimit=0x1cf1ab00

#链的Id，可以自定义，只要是一个大于0的整数即可。
chainId=$(date '+%Y%m%d')

gasLimitDecimal=485600000

function getConnection()
{
  ssh -o ConnectTimeout=2 -o PasswordAuthentication=no -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=no "$1@$2" "pwd" &>/dev/null
  # shellcheck disable=SC2181
  if [ $? = 0 ];then
    echo  "$1@$2 connect success"
  else
    echo  "$1@$2 connect failed"
  fi
}