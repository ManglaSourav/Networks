#!/bin/bash

bash vnltopo117.sh vhost1 setlossy eth1 100
bash vnltopo117.sh vhost2 setlossy eth0 100
sleep 60
bash vnltopo117.sh vhost1 status
bash vnltopo117.sh vhost2 status

for i in {1..6}
do
	wget http://172.29.5.23:16280
done

for j in {1..6}
do 
	wget http://172.29.5.27:16280
done

b=6
if [ $i == $b ]
then 
	    echo "Downloaded from server 1 $i times"
    else
	        echo "Some Mistake"
fi

if [ $j == $b ]
then
	    echo "Downloaded from server 2 $j times"
    else
	        echo "Some Mistake"
fi

bash backup1.sh
