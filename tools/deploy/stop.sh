#!/bin/bash

export port=30315

export execApp="sipe"

pid=$(lsof -i:${port}|grep ${execApp}|awk '{print $2}')

exitSuccess="true"

if [ "$pid" != "" ];then
	echo "${execApp} is running,try to kill it"
	kill -15 ${pid}
	while [[ -n $pid ]]; do
		sleep 1
		pid=$(lsof -i:${port}|grep ${execApp}|awk '{print $2}')
		if [ "$pid" != "" ];then
			echo "${execApp} is running,try to kill it"
			kill -15 ${pid}
		else
			if [ "$exitSuccess" == "true" ];then
			   echo "${execApp} exited success"
			   exitSuccess="false"
		    fi
		fi
	done
	if [ "$exitSuccess" == "true" ];then
	    echo "${execApp} exited success"
	    exitSuccess="false"
    fi
fi

