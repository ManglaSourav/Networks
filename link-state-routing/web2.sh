#!/bin/bash

bash vnltopo110.sh vhost1 setlossy eth2 100
bash vnltopo110.sh vhost3 setlossy eth0 100
sleep 30
bash vnltopo110.sh vhost1 status
bash vnltopo110.sh vhost3 status

for i in {1..6}
	do
		wget 172.29.4.167:16280
	done

	for j in {1..6}
	do
		wget http://172.29.4.171:16280
	done

b=6
if [ $i == $b ]
then
	echo "Downloaded from server 1 $i times"
	else
		echo "Error"
fi

if [ $j == $b ]
then
	echo "Downloaded from server 2 $j times"
	else
		echo "Error"
fi

bash vnltopo110.sh vhost1 setlossy eth2 0
bash vnltopo110.sh vhost3 setlossy eth0 0
