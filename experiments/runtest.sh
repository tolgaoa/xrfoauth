#!/bin/bash

clientc=5
for ((i=1;i<=$clientc;i++))
do
	declare clientn_$i=$(kubectl get pods -n xrf -o wide| grep xrfc$i | awk '{print $1}');
done


kubectl exec -n xrf $clientn_1 -c xrfc1 -- build/xappclient & 
kubectl exec -n xrf $clientn_2 -c xrfc2 -- build/xappclient & 
kubectl exec -n xrf $clientn_3 -c xrfc3 -- build/xappclient &
kubectl exec -n xrf $clientn_4 -c xrfc4 -- build/xappclient &
kubectl exec -n xrf $clientn_5 -c xrfc5 -- build/xappclient &
