#!/bin/bash

waitAllPods()
{
        wrnmsg "\tWaiting for all pods to be deployed"

        while [[ "$(kubectl get -n xrf pods --field-selector status.phase!=Running -o name)" != "" ]];
                do
                        wrnmsg "."
                        sleep 2
                done

        while [[ "$(kubectl get -n xrf pods | grep 'Error\|CrashLoopBackOff' )" != "" ]];
        do
                wrnmsg "."
                sleep 2
        done
        echo ""
}

wrnmsg()
{
        local message="$1"
        local bold=$(tput bold)
        local normal=$(tput sgr0)

        local color=$(tput setaf 4)
        local color_default=$(tput setaf 9)

        echo -en "${bold}${color}${message}${color_default}${normal}"
}

nousers=$1

echo "Deploying XRF Server"
kubectl apply -f ../xrfserver/deployment/dep.yaml
kubectl wait --for=condition=available --timeout=200s deployment/xrfs -n xrf

echo "Starting XRF client deployments"

xrfIP=$(kubectl get pods -n xrf -o wide| grep xrfs | awk '{print $6}');

for ((c=1;c<=$nousers;c++))
do
	sed -i "18s/.*/  name: xrfc$c/" ../xrfclient/deployment/dep.yaml
	sed -i "21s/.*/    app: xrfc$c/" ../xrfclient/deployment/dep.yaml
	sed -i "26s/.*/      app: xrfc$c/" ../xrfclient/deployment/dep.yaml
	sed -i "33s/.*/        app: xrfc$c/" ../xrfclient/deployment/dep.yaml
	sed -i "41s/.*/          value: \"$xrfIP\"/" ../xrfclient/deployment/dep.yaml

	kubectl apply -f ../xrfclient/deployment/dep.yaml
done

waitAllPods

