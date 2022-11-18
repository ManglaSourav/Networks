
ping 172.29.4.166 -c 2
ping 172.29.4.173 -c 2
ping 172.29.4.167 -c 2
ping 172.29.4.171 -c 2
ping 172.29.4.162 -c 2
ping 172.29.4.168 -c 2
ping 172.29.4.174 -c 2

# test between servers: ./vnltopo110.sh server1 ping 172.29.4.171

# To fail the link: ./vnltopo110.sh vhost1 setlossy eth1 100 ; ./vnltopo110.sh vhost2 setlossy eth0 100
# To bring the link back up: ./vnltopo110.sh vhost1 setlossy eth1 0 ; ./vnltopo110.sh vhost2 setlossy eth0 0
# To check the current loss rate: ./vnltopo110.sh vhost1 status