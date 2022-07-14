#!/bin/bash

iterations=$1
thc=$2

rm -r logs/clientSide
mkdir logs/clientSide
rm -r logs/serverSide
mkdir logs/serverSide

nousers=(20 30 40 50 60 70 80 90)
#nousers=(5)


for ((u=0;u<${#nousers[@]};u++))
do	
	lu=${nousers[$u]}; 

	mkdir logs/clientSide/clientc$lu
	mkdir logs/serverSide/clientc$lu

	for ((ite=1;ite<=$iterations;ite++))
	do

		mkdir logs/clientSide/clientc$lu/iter$ite
		mkdir logs/serverSide/clientc$lu/iter$ite

		/bin/bash ./deploy.sh $lu $thc
		sleep 2
		/bin/bash ./startclients.sh $lu $ite
		sleep 2
		/bin/bash ./undeploy.sh $lu
		sleep 2

	done
	echo "Finished processing for client count $lu"
done

