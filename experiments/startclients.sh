#!/bin/bash

nc=$1
nu=$2
tc=$3

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
        kubectl cp xrf/$clientPod:/root/xrfclient/src/latency.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfc$k.txt -c xrfc
done

kubectl cp xrf/$xrfpod:/root/xrfserver/src/latency.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/xrfslog.txt -c xrfs

xpid=$(kubectl exec -it -n xrf $xrfpod -c xrfs -- ps aux | grep xappoa | awk '{print $2}')
tpids=( $(ps aux -T -p $xpid | grep xappoa | awk '{print $3}') )

for ((t=0;t<${#tpids[@]};t++))
do
        tid=${tpids[$t]};

        kubectl exec -it -n xrf $xrfpod -c xrfs -- cat /proc/$tid/status | grep voluntary | awk '{print$2}' | tee ./logs/thr$tc/serverSide/clientc$nc/iter$nu/ctxts$t.txt

done
