#!/bin/bash

nc=$1

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

