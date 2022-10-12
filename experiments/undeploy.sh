#!/bin/bash


waitAllPods()
{
        wrnmsg "\tWaiting for all pods to be terminated"

        while [[ "$(kubectl get -n xrf pods --field-selector status.phase=Running -o name)" != "" ]];
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

kubectl delete deployment --all -n xrf
#for ((count=1;count<=$1;count++))
#do
#	kubectl delete deployment xrfc$count -n xrf
#done

waitAllPods
