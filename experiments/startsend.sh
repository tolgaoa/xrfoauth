#!/bin/bash


for ((k=1;k<=20;k++))
do
	/bin/bash ./deploy.sh 1 20
	sleep 2
	xrfpod=$(kubectl get pods -n xrf -o wide| grep xrfs | awk '{print $1}');
	xrfcrefpod=$(kubectl get pods -n xrf -o wide| grep xrfcref | awk '{print $1}');
	xrfcpod=$(kubectl get pods -n xrf -o wide| grep xrfc1 | awk '{print $1}');

	kubectl exec -n xrf $xrfpod -c xrfs -- build/xappoauth &
	sleep 1
	kubectl exec -n xrf $xrfcrefpod -c xrfc -- build/xappclient &
	sleep 1
	kubectl exec -n xrf $xrfcpod -c xrfc -- build/xappclient &

	sleep 10

	kubectl cp xrf/$xrfcrefpod:/root/xrfclient/src/latencyremote.txt ./logs/token/xrfctokremote$k.txt -c xrfc
	#kubectl cp xrf/$xrfcrefpod:/root/xrfclient/src/latencyremote.txt ./logs/token/xrfctokremote.txt -c xrfc

	kubectl cp xrf/$xrfcpod:/root/xrfclient/src/cllatency.txt ./logs/token/cllatencyrem$k.txt -c xrfc
	
	/bin/bash ./undeploy.sh 	
	sleep 2
done
