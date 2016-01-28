# Creating namespaces
# h1 and h2 will become the virtual hosts
ip netns add h1
ip netns add h2

# Create switches s1 s2 and s3
ovs-vsctl add-br s1
ovs-vsctl add-br s2
ovs-vsctl add-br s3

#enabling STP
ovs-vsctl set bridge s1 stp_enable=false
ovs-vsctl set bridge s2 stp_enable=false
ovs-vsctl set bridge s3 stp_enable=false

# Create links [ h1-eth0----eth1-s1-eth2----eth1-s2-eth3----eth0-h2]
#			   [                  \              /                 ]
#			   [                  eth3         eth2                ]
#			   [                    \          /                   ]
#			   [                    eth1     eth2                  ]
#			   [                      \      /                     ]
#			   [                       --s3--                      ]

#s1 connections to h1, s2 and s3
ip link add h1-eth0 type veth peer name s1-eth1
ip link add s1-eth2 type veth peer name s2-eth1
ip link add s1-eth3 type veth peer name s3-eth1

#s2 and s3 connections
ip link add s2-eth2 type veth peer name s3-eth2
#final connection h2 to s2
ip link add h2-eth0 type veth peer name s2-eth3


ip link show

# Move host ports into namespaces
ip link set h1-eth0 netns h1
ip link set h2-eth0 netns h2

ip netns exec h1 ip link show
ip netns exec h2 ip link show

# Connect switch ports to OVS
ovs-vsctl add-port s1 s1-eth1
ovs-vsctl add-port s1 s1-eth2
ovs-vsctl add-port s1 s1-eth3
ovs-vsctl add-port s2 s2-eth1
ovs-vsctl add-port s2 s2-eth2
ovs-vsctl add-port s2 s2-eth3
ovs-vsctl add-port s3 s3-eth1
ovs-vsctl add-port s3 s3-eth2

ovs-vsctl show

# Set up OpenFlow controller
ovs-vsctl set-controller s1 tcp:127.0.0.1
ovs-vsctl set-controller s2 tcp:127.0.0.1
ovs-vsctl set-controller s3 tcp:127.0.0.1

ovs-vsctl show

# Assigning IP addresses to interfaces and turning on the interfaces
ip netns exec h1 ifconfig h1-eth0 10.0.10.1
ip netns exec h1 ifconfig lo up
ip netns exec h2 ifconfig h2-eth0 10.0.10.2
ip netns exec h2 ifconfig lo up
ifconfig s1-eth1 up
ifconfig s1-eth2 up
ifconfig s1-eth3 up
ifconfig s2-eth1 up
ifconfig s2-eth2 up
ifconfig s2-eth3 up
ifconfig s3-eth1 up
ifconfig s3-eth2 up




 