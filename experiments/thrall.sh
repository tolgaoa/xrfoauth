#!/bin/bash

iterations=$1
thcount=(2 20)


for ((t=0;t<${#thcount[@]};t++))
do
        thc=${thcount[$t]};
	/bin/bash ./runall.sh $1 $thc

done
