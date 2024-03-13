#!/bin/bash
#主机操作系统
hostOS=""
function checkHostOS(){
	#文件存在，可能是ubuntu
	if [ -f "/etc/lsb-release" ]; then
		#显示一下
		cat /etc/lsb-release
	    if [ -f "/etc/issue" ]; then
	        issue=$(cat "/etc/issue"|grep "Ubuntu"|awk '{print $1}')
	        if [[ $issue == *Ubuntu* ]];then
	            hostOS="Ubuntu"
	        fi
	    fi
	fi

	if [ -f "/etc/redhat-release" ]; then
		#显示一下
		cat /etc/redhat-release
		release=$(cat "/etc/redhat-release"|awk '{print $1}')
		if [[ $release == *CentOS* ]];then
		    hostOS="CentOS"
		fi
	fi
}

#安装时间同步软件
function installNtpdateOnCentOS(){
	if [ ! -f "/usr/sbin/ntpdate" ]; then
		sudo yum install ntpdate -y
    fi
}
#安装时间同步软件
function installNtpdateOnUbuntu(){
    if [ ! -f "/usr/sbin/ntpdate" ]; then
		sudo apt-get install ntpdate -y
	fi
}
#设置为北京时间，并同步时间
function setTimeZone(){
	if [ -f "/usr/share/zoneinfo/Asia/Shanghai" ]; then
		rm -rf /etc/localtime
		ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    fi
    #同步时间
    ntpdate cn.ntp.org.cn
}

#检查操作系统发行版本
checkHostOS

if [[ $hostOS == "Ubuntu" ]];then
	echo "I am Ubuntu"
	installNtpdateOnUbuntu
	setTimeZone

fi

if [[ $hostOS == "CentOS" ]];then
	echo "I am CentOS"
	installNtpdateOnCentOS
	setTimeZone
fi