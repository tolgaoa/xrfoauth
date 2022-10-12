#!/bin/bash

iterations=$1
thc=$2

rm -r logs/thr$2/
mkdir logs/thr$2/

mkdir logs/thr$2/serverSide
mkdir logs/thr$2/clientSide

nousers=(400)

for ((u=0;u<${#nousers[@]};u++))
do
        lu=${nousers[$u]};

        mkdir logs/thr$2/clientSide/clientc$lu
        mkdir logs/thr$2/serverSide/clientc$lu

        for ((ite=1;ite<=$iterations;ite++))
        do

                mkdir logs/thr$2/clientSide/clientc$lu/iter$ite
                mkdir logs/thr$2/serverSide/clientc$lu/iter$ite

                /bin/bash ./deploy.sh $lu $thc
                sleep 2
                /bin/bash ./startclients.sh $lu $ite $thc
                sleep 2
                /bin/bash ./undeploy.sh $lu
                sleep 2

        done
        echo "Finished processing for client count $lu"
done
