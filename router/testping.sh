#!/bin/bash
for i in 172.29.10.33 172.29.10.34 172.29.10.51 172.29.10.52 172.29.10.38 172.29.10.54 172.29.10.40 172.29.10.41
do
echo "Pinging $i"
ping -c 5 $i

done

