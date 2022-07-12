#!/bin/bash

nc=$1
nu=$2

xrfpod=$(kubectl get pods -n xrf -o wide| grep xrfs | awk '{print $1}');

kubectl exec -n xrf $xrfpod -c xrfs -- build/xappoauth & 
#sleep 2

declare -A clients=()
for ((i=1;i<=$nc;i++))
do
	clients[$i]=$(kubectl get pods -n xrf -o wide| grep xrfc$i | awk '{print $1}');
done

for ((j=1;j<=$nc;j++))
do
	#echo ${clients[$j]}
	kubectl exec -n xrf ${clients[$j]} -c xrfc -- build/xappclient & 
	#sleep 1
done

#sleep 10

for ((k=1;k<=$nc;k++))
do 
	clientPod=$(kubectl get pods -n xrf -o wide| grep xrfc$k | awk '{print $1}');
	kubectl cp xrf/$clientPod:/root/xrfclient/src/latency.txt ./logs/clientSide/clientc$nc/iter$nu/xrfc$k.txt -c xrfc
done

kubectl cp xrf/$xrfpod:/root/xrfserver/src/latency.txt ./logs/serverSide/clientc$nc/iter$nu/xrfslog.txt -c xrfs

