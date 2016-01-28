
#Remove everything
ovs-vsctl del-controller s1 
ovs-vsctl del-controller s2 
ovs-vsctl del-controller s3 
ip netns exec h1 ifconfig up lo
ip netns exec h2 ifconfig up lo
ifconfig s1-eth1 lo
ifconfig s1-eth2 lo
ifconfig s1-eth3 lo
ifconfig s2-eth1 lo
ifconfig s2-eth2 lo
ifconfig s2-eth3 lo
ifconfig s3-eth1 lo
ifconfig s3-eth2 lo
ovs-vsctl del-port s1 s1-eth1
ovs-vsctl del-port s1 s1-eth2
ovs-vsctl del-port s1 s1-eth3
ovs-vsctl del-port s2 s2-eth1
ovs-vsctl del-port s2 s2-eth2
ovs-vsctl del-port s2 s2-eth3
ovs-vsctl del-port s3 s3-eth1
ovs-vsctl del-port s3 s3-eth2

ip netns del h1
ip netns del h2