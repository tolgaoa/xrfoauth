#!/bin/bash

nc=$1
nu=$2
tc=$3

xrfpod=$(kubectl get pods -n xrf -o wide| grep xrfs | awk '{print $1}');

#kubectl exec -n xrf $xrfpod -c xrfs -- build/xappoauth &
#sleep 2

declare -A clients=()
for ((i=1;i<=$nc;i++))
do
        clients[$i]=$(kubectl get pods -n xrf -o wide| grep xrfc$i | awk '{print $1}');
done

kubectl exec -n xrf $xrfpod -c xrfs -- build/xappoauth &
sleep 1
for ((j=1;j<=$nc;j++))
do
        #echo ${clients[$j]}
        kubectl exec -n xrf ${clients[$j]} -c xrfc -- build/xappclient &
        #sleep 1
done

sleep 10

for ((k=1;k<=$nc;k++))
do
        clientPod=$(kubectl get pods -n xrf -o wide| grep xrfc$k | awk '{print $1}');
        kubectl cp xrf/$clientPod:/root/xrfclient/src/latency.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfc$k.txt -c xrfc
        #kubectl cp xrf/$clientPod:/root/xrfclient/src/latencyauth.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfcauth$k.txt -c xrfc
        #kubectl cp xrf/$clientPod:/root/xrfclient/src/latencyreg.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfcreg$k.txt -c xrfc
        #kubectl cp xrf/$clientPod:/root/xrfclient/src/latencydisc.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfcdisc$k.txt -c xrfc
        #kubectl cp xrf/$clientPod:/root/xrfclient/src/latencytoken.txt ./logs/thr$tc/clientSide/clientc$nc/iter$nu/xrfctok$k.txt -c xrfc
done

kubectl cp xrf/$xrfpod:/root/xrfserver/src/latency.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/xrfslog.txt -c xrfs
#kubectl cp xrf/$xrfpod:/root/xrfserver/src/latencyAuth.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/authlogs.txt -c xrfs
#kubectl cp xrf/$xrfpod:/root/xrfserver/src/latencyReg.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/reglogs.txt -c xrfs
#kubectl cp xrf/$xrfpod:/root/xrfserver/src/latencyDI.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/disclogs.txt -c xrfs
#kubectl cp xrf/$xrfpod:/root/xrfserver/src/latency.txt ./logs/thr$tc/serverSide/clientc$nc/iter$nu/tokenlogs.txt -c xrfs

xpid=$(kubectl exec -it -n xrf $xrfpod -c xrfs -- ps aux | grep xappoa | awk '{print $2}')
tpids=( $(kubectl exec -it -n xrf $xrfpod -c xrfs -- ps aux -T -p $xpid | grep build/x | awk '{print $3}') )

for ((t=0;t<${#tpids[@]};t++))
do
        tid=${tpids[$t]};

	PROCESS_STAT=($(kubectl exec -it -n xrf $xrfpod -c xrfs -- sed -E 's/\([^)]+\)/X/' "/proc/$tid/stat"))
	PROCESS_UTIME=${PROCESS_STAT[13]}
	PROCESS_STIME=${PROCESS_STAT[14]}
	PROCESS_STARTTIME=${PROCESS_STAT[21]}
	SYSTEM_UPTIME_SEC=$(kubectl exec -it -n xrf $xrfpod -c xrfs | tr . ' ' </proc/uptime | awk '{print $1}')

	CLK_TCK=$(kubectl exec -it -n xrf $xrfpod -c xrfs | getconf CLK_TCK)

	let PROCESS_UTIME_SEC="$PROCESS_UTIME / $CLK_TCK"
	let PROCESS_STIME_SEC="$PROCESS_STIME / $CLK_TCK"
	let PROCESS_STARTTIME_SEC="$PROCESS_STARTTIME / $CLK_TCK"

	let PROCESS_ELAPSED_SEC="$SYSTEM_UPTIME_SEC - $PROCESS_STARTTIME_SEC"
	let PROCESS_USAGE_SEC="$PROCESS_UTIME_SEC + $PROCESS_STIME_SEC"
	let PROCESS_USAGE="$PROCESS_USAGE_SEC * 100 / $PROCESS_ELAPSED_SEC"

        kubectl exec -it -n xrf $xrfpod -c xrfs -- cat /proc/$tid/status | grep voluntary | awk '{print$2}' | tee -a >> ./logs/thr$tc/serverSide/clientc$nc/iter$nu/ctxts.txt

        kubectl exec -it -n xrf $xrfpod -c xrfs -- cat /proc/$tid/stat | awk '{print ($13+$14)}' | awk '{print $1}' | tee -a >> ./logs/thr$tc/serverSide/clientc$nc/iter$nu/cpuusagetick.txt
        echo $PROCESS_USAGE | tee -a >> ./logs/thr$tc/serverSide/clientc$nc/iter$nu/cpuusageperc.txt
        echo $PROCESS_UTIME_SEC | tee -a >> ./logs/thr$tc/serverSide/clientc$nc/iter$nu/cpuusageusermod.txt
        echo $PROCESS_STIME_SEC | tee -a >> ./logs/thr$tc/serverSide/clientc$nc/iter$nu/cpuusagekernelmod.txt

done

