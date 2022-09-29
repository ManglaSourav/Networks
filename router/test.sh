#!/bin/bash

echo "Downloading from server 3"
wget http://172.29.9.65:16280  
sleep 2
echo "Downloading from server 4"
wget http://172.29.9.66:16280
sleep 2
echo "Downloading from server 2"
wget http://172.29.9.83:16280

sleep 2
echo "Downloading from server 1"
wget http://172.29.9.84:16280
sleep 2
echo "Downloading 64mb server 1"
wget http://172.29.9.84:16280/64MB.bin
sleep 30
echo " Downloading 64mb from server 2"
wget http://172.29.9.83:16280/64MB.bin						
sleep 30
echo "Downloading 64mb server 3"
wget http://172.29.9.66:16280/64MB.bin
sleep 30
echo "Downloading 64mb server 4"
wget http://172.29.9.65:16280/64MB.bin
sleep 30
# echo "Downloading from server 1"
# wget  http://172.29.10.33:16280
# sleep 2
# echo"Downloading from server 2"
# wget  http://172.29.10.34:16280
# sleep 2
# echo "Downloading from server 3"
# wget  http://172.29.10.51:16280
# sleep 2
# echo "Downloading from server 4"
# wget  http://172.29.10.52:16280
# sleep 2
echo "Done"

