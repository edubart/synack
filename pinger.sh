#!/bin/bash

cleanup ()
{
  kill -s SIGTERM $!
  exit 0
}

trap cleanup SIGINT SIGTERM

if [ "$#" -ne 3 ]; then
  echo "Usage $0 <host> <tcp port> <out>"
  exit
fi

echo Pinging host $1:$2 and saving to $3

while true; do
  (./synack -i eth0 -h $1 -p $2 -t 60 -q -J >> $3) &
  wait $!
done

