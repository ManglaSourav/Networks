#!/bin/bash
for i in 172.29.9.65 172.29.9.66 172.29.9.83 172.29.9.84
echo "Pinging $i"
ping -c 5 $i

done

