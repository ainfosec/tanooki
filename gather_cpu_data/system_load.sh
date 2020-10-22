#! /bin/bash 

# get the system load every 15 minutes 
while true
do
	cd ./data
	# get the dir name
	DIR=$(ls -d */)
	cd ..
	# get the latest file 
	[ ! -z $DIR ] && CURRENT=$(ls ./data/$DIR -tr | tail -n 2 | awk '$1 !="METADATA"' | tail -n 1)
	# avg system load 
	LOAD=$(cat /proc/loadavg)
	echo $LOAD","$CURRENT >> ./data/$USER'-SYSTEM_LOAD.txt'  
	sleep 900
done

