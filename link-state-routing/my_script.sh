
ping 172.29.4.166 -c 2
ping 172.29.4.173 -c 2
ping 172.29.4.167 -c 2
ping 172.29.4.171 -c 2
ping 172.29.4.162 -c 2
ping 172.29.4.168 -c 2
ping 172.29.4.174 -c 2

# test between servers: ./vnltopo110.sh server1 ping 172.29.4.171
# ./vnltopo110.sh server2 ping 172.29.4.167

# To fail the link: ./vnltopo110.sh vhost1 setlossy eth1 100 ; ./vnltopo110.sh vhost2 setlossy eth0 100
# To bring the link back up: ./vnltopo110.sh vhost1 setlossy eth1 0 ; ./vnltopo110.sh vhost2 setlossy eth0 0
# To check the current loss rate: ./vnltopo110.sh vhost1 status



# For topology #109
# ping 172.29.4.146 -c 2
# ping 172.29.4.148 -c 2
# ping 172.29.4.152 -c 2
# ping 172.29.4.149 -c 2
# ping 172.29.4.150 -c 2
# ping 172.29.4.157 -c 2
# ping 172.29.4.153 -c 2
# ping 172.29.4.154 -c 2
# ping 172.29.4.158 -c 2
# ping 172.29.4.151 -c 2
# ping 172.29.4.155 -c 2

# test between servers: 
# ./vnltopo109.sh server1 ping 172.29.4.155
# ./vnltopo109.sh server2 ping 172.29.4.151

# To fail the link:
#  ./vnltopo109.sh vhost1 setlossy eth1 100 ; ./vnltopo109.sh vhost2 setlossy eth0 100
# To bring the link back up: 
# ./vnltopo109.sh vhost1 setlossy eth1 0 ; ./vnltopo109.sh vhost2 setlossy eth0 0
# To check the current loss rate: ./vnltopo109.sh vhost1 status
