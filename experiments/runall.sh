#!/bin/bash

nousers=$1

/bin/bash ./deploy.sh $nousers
sleep 2
/bin/bash ./startclients.sh $nousers
sleep 2
#/bin/bash ./undeploy.sh $nousers
