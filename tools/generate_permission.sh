#!/bin/bash

# shellcheck disable=SC2046
# shellcheck disable=SC2164
workdir=$(cd $(dirname "$0"); pwd)

cd "$workdir/../permission/contract/"

solc --version>>/dev/null

if [ $? -eq 0 ];then
  # shellcheck disable=SC2086
  solc --optimize --bin  -o $workdir/deploy/ --overwrite Permission.sol
else
  echo "please install solc first"
  exit 1
 fi
