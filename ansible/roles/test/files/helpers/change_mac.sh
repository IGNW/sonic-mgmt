#!/bin/bash

for i in $(ifconfig | grep eth | cut -f 1 -d ' ')
do
  port="${i//:}"
  prefix=$(ifconfig $port | grep ether | cut -c15-29)
  suffix=$( printf "%02x" ${port##eth})
  mac=$prefix$suffix
  echo $port $mac
  ifconfig $port hw ether $mac
done
