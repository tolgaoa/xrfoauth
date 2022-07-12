#!/bin/bash

iterations=$1

rm -r logs/clientSide
mkdir logs/clientSide
rm -r logs/serverSide
mkdir logs/serverSide

nousers=(1 2 5 10 15 20 25 30 35 40 50 60 70 80 90 100)
#nousers=(5)


for ((u=0;u<${#nousers[@]};u++))
do	
	lu=nousers[u]; 

	mkdir logs/clientSide/clientc$u
	mkdir logs/serverSide/clientc$u

	for ((ite=1;ite<=$iterations;ite++))
	do

		mkdir logs/clientSide/clientc$lu/iter$ite
		mkdir logs/serverSide/clientc$lu/iter$ite

		/bin/bash ./deploy.sh $lu
		sleep 2
		/bin/bash ./startclients.sh $lu $ite
		sleep 2
		/bin/bash ./undeploy.sh $lu
		sleep 2

	done
	echo "Finished processing for client count $lu"
done

