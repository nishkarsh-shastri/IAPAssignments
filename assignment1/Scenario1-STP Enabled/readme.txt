*************INSTRUCTIONS TO RUN NETWORK TOPOLOGY***************************

***STP ENABLED TOPOLOGY***
1) sudo bash
2) Run the commands written in Create_topology.sh

### TOPOLOGY IS SET UP ### Capture from 8 interfaces of s1,s2 and s3 

sudo wireshark

### Run wireshark in the hosts
4) sudo ip netns exec h1 wireshark
5) sudo ip netns exec h2 wireshark

### Set up executable client and server files ###
4) Navigate to the datagram_client.c and datagram_server.c containing folders
5) gcc datagram_server.c -o server
6) gcc datagram_client.c -o client
7) create two separate terminals in the same folder

### Attach clients and server to the hosts ###

8) sudo ip netns exec h2 ./server
9) sudo ip netns exec h1 ./client

***Remove hosts and switches
10) run the commands of delete_topology.sh to in bash at root to remove the switches and hosts.
