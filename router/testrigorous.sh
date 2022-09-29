#!/bin/bash
b=6
echo " Continuously  Downloading File from server 1"
for i in {1..6}
do 
  wget http://172.29.10.33:16280
  sleep 0.5
done
echo " Continuously  Downloading File from server 2"
for j in {1..6}
do	
  wget http://172.29.10.34:16280
  echo "Done $j"
  sleep 0.5
done
echo "Downloading from server 3"
for k in {1..6}
do
	  wget http://172.29.10.51:16280
	  echo "Done $k"
	  sleep 0.5
done
echo"Downloading fro server 4"
for l in {1..6}
do
	          wget http://172.29.10.52:16280
		  echo "Done $l"
	          sleep 0.5
done
echo"Downloading from all servers 6 times"
for m in {1..6}
do
	wget http://172.29.10.33:16280
	sleep 0.5
	wget http://172.29.10.34:16280
	sleep 0.5
	wget http://172.29.10.51:16280
	sleep 0.5
	wget http://172.29.10.52:16280
	sleep 0.5
done
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
if [ $k == $b ]
then
    echo "Downloaded from server 3 $b times"
else
    echo "Some Mistake"
fi
if [ $l == $b ]
then
    echo "Downloaded from server 4 $l times"
else
    echo "Some Mistake"
fi
if [ $m == $b ]
then
    echo "Downloaded packet from all server $m times"
else 
    echo" Some Mistake"
fi





