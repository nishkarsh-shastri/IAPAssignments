from pox.lib.revent import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet import arp, icmp
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST, ETHER_ANY
from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST
# from pox.proto.arp_helper import *
import time

log = None
if core != None:
	log = core.getLogger()

SWITCH_TYPE_INVALID     = 0x00
SWITCH_TYPE_HUB         = 0x01
SWiTCH_TYPE_ROUTER      = 0x02

#TODO: remove this table, and use some file
rtable = {}
rtable["R1"] = [
			['10.0.0.0/16', '192.0.4.2', 'R1-eth2'],
			['10.0.3.0/24', '192.0.1.2', 'R1-eth3'],
			['10.0.1.0/24', '10.0.1.1', 'R1-eth1'],
			['192.0.0.0/16', '192.0.4.2', 'R1-eth2'],
			['19.0.1.0/24', '192.0.1.2', 'R1-eth3'],
		]
rtable["R2"] = [
			['10.0.0.0/16', '192.0.3.2', 'R2-eth2'],
			['10.0.1.0/24', '192.0.4.1', 'R2-eth1'],
			['10.0.2.0/24', '10.0.2.1', 'R2-eth3'],
			['192.0.0.0/16', '192.0.3.2', 'R2-eth2'],
			['192.0.4.0/24', '192.0.4.1', 'R2-eth1'],
		]

rtable["R4"] = [
			['10.0.0.0/16', '192.0.2.1', 'R4-eth2'],
			['10.0.2.0/24', '192.0.3.1', 'R4-eth1'],
			['10.0.4.0/24', '10.0.4.1', 'R4-eth3'],
			['192.0.0.0/16', '192.0.2.1', 'R4-eth2'],
			['192.0.3.0/24', '192.0.3.1', 'R4-eth1'],
		]
rtable["R3"] = [
			['10.0.0.0/16', '192.0.1.1', 'R3-eth1'],
			['10.0.4.0/24', '192.0.2.2', 'R3-eth3'],
			['10.0.3.0/24', '10.0.3.1', 'R3-eth2'],
			['192.0.0.0/16', '192.0.1.1', 'R3-eth1'],
			['192.0.2.0/24', '192.0.2.2', 'R3-eth3'],
		]

ROUTERS_IPS = {
			"R1-eth1" : "10.0.1.1",
			"R1-eth2" : "192.0.4.1",
			"R2-eth1" : "192.0.4.2",
			"R2-eth2" : "192.0.3.1",
			"R4-eth1" : "192.0.3.2",
			"R1-eth3" : "192.0.1.1",
			"R3-eth1" : "192.0.1.2",
			"R3-eth2" : "10.0.3.1",
			"R3-eth3" : "192.0.2.1",
			"R4-eth2" : "192.0.2.2",
			"R2-eth3" : "10.0.2.1",
			"R4-eth3" : "10.0.4.1"
		}

import datetime
import struct
import socket
def ip2int(addr):
	return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
	return socket.inet_ntoa(struct.pack("!I", addr))

# ROUTERS_IP_2_PORT = {}


class RoutingEntry():
	def __init__(self, txtEntry = []):
		self.netIP          = self.parseTextIp(txtEntry[0])
		self.netMaskCnt     = self.parseTextMaskCnt(txtEntry[0])
		self.netMask        = self.parseTextMask(txtEntry[0])
		self.nextHopIp      = self.parseTextIp(txtEntry[1])
		self.intf           = txtEntry[2]
		self.nextHopIpAddr  = IPAddr(self.textedIP(self.nextHopIp))
		self.netIP         &= self.netMask

	def __str__(self):
		return "netIP: %s/%s, nextHopIp: %s, intf: %s"%(self.textedIP(self.netIP), self.netMaskCnt, self.nextHopIpAddr, self.intf)
	
	def matchTextIp(self, ipText):
		return self.match(self.parseTextIp(ipText))

	def match(self, ip):
		ipp = ip & self.netMask
		return ipp == self.netIP

	def parseTextMaskCnt(self, ip):
		slash = ip.find("/")
		if slash < 0:
			raise Exception("Invalid mask")
		mask = ip[slash + 1 :]
		mask = int(mask)
		if mask < 0 or mask > 32:
			raise Exception("Invalid mask")
		return mask

	def parseTextMask(self, ip):
		mask = self.parseTextMaskCnt(ip)
		intMask = 1
		intMask <<= mask
		intMask -= 1
		intMask <<= (32 - mask)
		return intMask
	
	def parseTextIp(self, ip):
		slash = ip.find("/")
		if slash >= 0:
			ip = ip[:slash]
		ipseg = ip.split(".")
		if len(ipseg) != 4:
			raise Exception("Invalid ip")
		intIP = 0
		for s in ipseg:
			i = int(s)
			if i < 0 or i > 255:
				raise Exception("Invalid ip")
			intIP = intIP << 8
			intIP += i
		return intIP

	def textedIP(self, intIP):
		s = ".".join([ "%s"%((intIP & (255<<(i*8)))>>(i*8)) for i in xrange(3, -1, -1)])
		return s

	def getMatchSize(self):
		return self.netMaskCnt

class RoutingTable():
	def __init__(self):
		self.routingEntries = []
	
	def addEntry(self, entry = []):
		if type(entry) != list:
			raise Exception("Invalid entry")
		if len(entry) != 3:
			raise Exception("Invalid entry: Routing entry must have 3 string fields")
		for st in entry:
			if type(st) != str:
				raise Exception("Invalid entry: Routing entry must have 3 string fields")

		r = RoutingEntry(entry)
		self.routingEntries.append(r)

	def addEntries(self, entries):
		if type(entries) != list:
			raise Exception("Invalide Table")

		for entry in entries:
			self.addEntry(entry)

	def getMatchedEntry(self, ip):
		if ip == None:
			return None
		ip = str(ip)
		matchCnt = -1
		resRoute = None
		for route in self.routingEntries:
			if route.matchTextIp(ip) and matchCnt < route.netMaskCnt:
				matchCnt = route.netMaskCnt
				resRoute = route
		
		return resRoute
	
	def __str__(self):
		return "[" + ", ".join(["<"+str(r)+">" for r in self.routingEntries]) + "]"


HELLO_INT = 15
class InterfaceData():
	"""
		An interface within a pwospf router is defined by the following values:

		32 bit ip address  - IP address of associated interface
		32 bit mask mask   - subnet mask of assocaited interface
		16 bit helloint    - interval in seconds between HELLO broadcasts
		list [
			32 bit neighbor id - ID of neighboring router.
			32 bit neighbor ip - IP address of neighboring router's interface this
			interface is directly connected to.
		]
	"""
	def __init__(self, ip):
		self.ip = ip2int(ip) # 32-bit IP address of associated interface
		self.mask = ip2int("255.255.255.0") # 32-bit subnet mask of associated interface
		self.helloint = HELLO_INT # 16-bit interval in seconds between HELLO broadcasts
		self.neighbors = {} # neighbors is a dictionary of tuples
		# Each tuple consist of neighbor_id, timestamp

	def add_neighbor(self, neighbor_id, neighbor_ip, timestamp):
		self.neighbors[neighbor_ip] = (neighbor_id, timestamp)


PWOSPF_PROTOCOL = 14
PWOSPF_MIN_LEN = 24
"""
Type   Description
________________________________
1      Hello
4      Link State Update
"""
PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4
HELLO_MIN_LEN = 32
LSU_MIN_LEN = 32
ADVERTISEMENT_SIZE = 12

ALLSPFRouters = ip2int("224.0.0.5")



class RouterHandler(EventMixin):
	def __init__(self, connection, *ka, **kw):
		self.connection = connection
		self.name = ""
		self.type = SWITCH_TYPE_INVALID
		self.routingInfo = None
		log.debug("Handler: ka:" + str(ka) + " kw: " + str(kw))
		self.listenTo(connection)
		self.port2Mac = {}
		self.intf2Port = {}
		self.port2intf = {}
		self.arpTable = {}
		self.hwadr2Port = {}
		self.outstandingarp = {} #just key:ip and val timestamp(later`)
		self.queuedMsgForArp = {} #nested
		self.ARP_TIMEOUT = 4
		self.myips  = []

		########### PWOSPF data members
		# Router Information
		self.router_id = 0 
		self.area_id = 0
		self.lsuint = 30 # Default value
		# Interface Information
		self.interfaces = {}
		"""
		We want to make a adjacency graph of Routers and interfaces
		Each node is router
		Therefore topology_database will be a dictionary of router_id to list of neighbors
		Here each entry in this list is (subnet, mask, router_id) tuple
		"""
		self.topology_database = {}
		# We also need a dictionary of sequence numbers because we are implementing
		# flooding and don't want to send old packets
		self.topology_sequence_no = {}
		

		self.initialize_controller()

		########### PWOSPF data population
		self.initialize_pwospf_data()
	
	def initialize_controller(self):
		for port in self.connection.features.ports:
			if self.name == "":
				self.name = port.name[:2]
			if port.name.find("-") >= 0:
				self.port2Mac[port.port_no] = port.hw_addr
				self.intf2Port[port.name] = port.port_no
				self.port2intf[port.port_no] = port.name
				if port.name in ROUTERS_IPS:
#                     ROUTERS_IP_2_PORT[ROUTERS_IPS[port.name]] = port.hw_addr
					self.myips.append(ROUTERS_IPS[port.name])

			log.debug(port.name + str(port.__dict__))
		
		if self.name[0] == "S":
			self.type = SWITCH_TYPE_HUB
		elif self.name[0] == "R":
			self.type = SWiTCH_TYPE_ROUTER
		if self.name in rtable:
			self.routingInfo = RoutingTable()
			self.routingInfo.addEntries(rtable[self.name])

	def initialize_pwospf_data(self):
		# By default it is the IP of the 0th interface of the router
		self.router_id = ip2int(self.myips[0])
		
		self.interfaces = {}
		for port_name, port_no in self.intf2Port.iteritems():
			interface = InterfaceData()
			interface.ip = ip2int(ROUTERS_IPS[port_name])

			self.interfaces[port_no] = interface

	def _handle_PacketIn (self, event):
		#log.debug("Packet In event in router %s"%self.name)
		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

#         packet_in = event.ofp # The actual ofp_packet_in message.
		
		if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
			self.drop_packet(event)
			return

		if self.type == SWITCH_TYPE_HUB:
			self.act_like_hub(event, packet)
#             self.act_like_l2switch(event, packet)
			
		elif self.type == SWiTCH_TYPE_ROUTER:
			self.act_like_router(event, packet)
			#log.debug("%s: Just implemented"%self.name)
		else:
			log.warning("Unhandled switch type")

	def drop_packet(self, event, duration = None):
		"""
		Drops this packet and optionally installs a flow to continue
		dropping similar ones for a while
		"""
		if duration is not None:
			if not isinstance(duration, tuple):
				duration = (duration,duration)
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(packet)
			msg.idle_timeout = duration[0]
			msg.hard_timeout = duration[1]
			msg.buffer_id = event.ofp.buffer_id
			self.connection.send(msg)
		elif event.ofp.buffer_id is not None:
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port
			self.connection.send(msg)

	def act_like_hub(self, event, packet):
		packet_in = event.ofp
		match = of.ofp_match.from_packet(packet)
		msg = of.ofp_flow_mod()
		msg = of.ofp_packet_out()
		msg.data = packet_in
		
		#log.debug("match info at %s: %s"%(self.name, match))

		# Add an action to send to the specified port
		action = of.ofp_action_output(port = of.OFPP_ALL)
		msg.actions.append(action)

		# Send message to switch
		self.connection.send(msg)
	
	def act_like_l2switch(self, event, packet):
		dst_port = None
		self.hwadr2Port[packet.src] = event.port
		if packet.dst not in (ETHER_ANY, ETHER_BROADCAST) and not packet.dst.is_multicast:
			dst_port = self.hwadr2Port.get(packet.dst, None)
		if dst_port is None:
			packet_in = event.ofp
			match = of.ofp_match.from_packet(packet)
			msg = of.ofp_flow_mod()
			msg = of.ofp_packet_out()
			msg.data = packet_in
			
			#log.debug("match info at %s: %s"%(self.name, match))
	
			# Add an action to send to the specified port
			action = of.ofp_action_output(port = of.OFPP_ALL)
			msg.actions.append(action)
	
			# Send message to switch
			self.connection.send(msg)
		else:
				msg = of.ofp_flow_mod()
				msg.match.dl_dst = packet.src
				msg.match.dl_src = packet.dst
				msg.actions.append(of.ofp_action_output(port = event.port))
				event.connection.send(msg)
			
				# This is the packet that just came in -- we want to
				# install the rule and also resend the packet.
				msg = of.ofp_flow_mod()
				msg.data = event.ofp # Forward the incoming packet
				msg.match.dl_src = packet.src
				msg.match.dl_dst = packet.dst
				msg.actions.append(of.ofp_action_output(port = dst_port))
				event.connection.send(msg)

		   
	def act_like_router(self, event, packet):
		if packet.find("arp"):
			self.handle_arp_packet(event, packet)
		elif packet.find("ipv4"):
			self.handle_ipv4_packet(event, packet)
		else:
			self.drop_packet(event)

	def handle_ipv4_packet(self, event, packet):
		match = of.ofp_match.from_packet(packet)
		rd = self.routingInfo.getMatchedEntry(match.nw_dst)
		rs = self.routingInfo.getMatchedEntry(match.nw_src)

		if packet.protocol == PWOSPF_PROTOCOL:
			self.handle_pwospf_packet(event, packet)

		if match.nw_dst in self.myips:
			log.debug("%s: rs: %s, rs: %s"%(self.name, rs, rd))
			if packet.find("icmp") and packet.find("icmp").type == pkt.TYPE_ECHO_REQUEST:
					self.send_icmp_msg_small(packet, match, event)
		else:
			log.debug("%s: its a ip pkt match: %s"%(self.name, match))
			if rd is not None:
					self.forward_pkt_to_next_hop(packet, match, event, rd)
			else:
				self.send_icmp_msg_small(packet, match, event, pkt.TYPE_DEST_UNREACH, packet)
				#self.drop_packet(event)

	def handle_pwospf_packet(self, event, packet):
		payload = packet.payload
		#TODO: checksum
		"""
		PWOSPF Packet Header Format
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Version #   |     Type      |         Packet length         |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                          Router ID                            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           Area ID                             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|           Checksum            |             Autype            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		"""
		(version, pwospf_type, packet_length, router_id, area_id, checksum, 
			autype, auth) = struct.unpack('!BBHIIHHQ', payload[:PWOSPF_MIN_LEN])
		if pwospf_type == PWOSPF_HELLO_TYPE:
			self.handle_hello_packet(event, packet)
		elif pwospf_type == PWOSPF_LSU_TYPE:
			self.handle_lsu_packet(event, packet)
		else:
			log.error("Incorrect type of PWOSPF packet")

	def handle_hello_packet(self, event, packet):
		payload = packet.payload
		scrip = ip2int(packet.srcip)
		dstip = ip2int(packet.dstip)
		"""
		HELLO Packet Format 
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Version #   |       1       |         Packet length         |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                          Router ID                            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           Area ID                             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|           Checksum            |             Autype            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                        Network Mask                           |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|         HelloInt              |           padding             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		"""
		(version, pwospf_type, packet_length, router_id, area_id, checksum, 
			autype, auth, net_mask, helloint, padding) = struct.unpack('!BBHIIHHQIHH', payload[:HELLO_MIN_LEN])

		#TODO: Check if packet is correct or not (CHECKSUM)
		if(dstip != ALLSPFRouters):
			# not a correct HELLO packet
			return
		"""
		If the packet is from a yet to be identified neighbor and no other neighbors have been
		discovered off of the incoming interface, the router will add the neighbor to
		the interface.  If the packet is from a known neighbor, the router will mark
		the time the packet was received to track the uptime of its neighbor.
		"""
		# Simply add neighbor of this interface
		port_no = event.port
		neighbor_id = router_id
		neighbor_ip = srcip
		timestamp = datetime.datetime.now()
		interfaces[port_no].add_neighbor(neighbor_id, neighbor_ip, timestamp)
	
	def check_and_update_database(self, router_id, neighbors, sequence_no):
		existing_neighbors = self.topology_database[router_id]
		if not (set(neighbors) ^ set(existing_neighbors)): #symmetric difference
			# no difference found
			return False

		self.topology_database[router_id] = existing_neighbors
		self.topology_sequence_no[router_id] = sequence_no
		return True

	def recalcuate_routing_table(self):
		# We have to calculate routing table from the topology_database
		# Each element in the queue is a (current node, next hop) tuple
		# We construct node to interface mapping in parallel

		visited, queue = set(), [(self.router_id, None)]
		while queue:
			vertex_router_id, next_hop = queue.pop(0)
			if vertex_router_id not in visited:
				visited.add(vertex)
				neighbors = set(self.topology_database[vertex_router_id]) - visited
				queue.extend(neighbors)
		

	def handle_lsu_packet(self, event, packet):
		payload = packet.payload
		scrip = ip2int(packet.srcip)
		dstip = ip2int(packet.dstip)
		"""
		LSU Packet Format
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Version #   |       4       |         Packet length         |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                          Router ID                            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           Area ID                             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|           Checksum            |             Autype            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                       Authentication                          |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|     Sequence                |          TTL                    |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                      # advertisements                         |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                               |
		+-                                                            +-+
		|                  Link state advertisements                    |
		+-                                                            +-+
		|                              ...                              |
		"""
		(version, pwospf_type, packet_length, router_id, area_id, checksum, 
			autype, auth, sequence_no, ttl, n_advertisements) = struct.unpack('!BBHIIHHQHHI', payload[:LSU_MIN_LEN])
		advertisements = payload[LSU_MIN_LEN:]

		# Extract the advertisements
		"""
		Link state advertisements

		Each link state update packet should contain 1 or more link state
		advertisements.  The advertisements are the reachable routes directly
		connected to the advertising router.  Routes are in the form of the subnet,
		mask and router neighor for the attached link. Link state advertisements
		look specifically as follows:

		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           Subnet                              |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           Mask                                |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                         Router ID                             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		"""
		neighbors = []
		for i in range(n_advertisements):
			(ad_subnet, ad_mask, ad_router_id) = struct.unpack('!III', advertisements[:ADVERTISEMENT_SIZE])
			neighbors.append((ad_subnet, ad_mask, ad_router_id))
			if i != (n_advertisements-1):
				advertisements = advertisements[ADVERTISEMENT_SIZE:]

		########################## SANITY CHECKS ####################################
		# Drop the packet when the packet received has started from self
		if router_id == self.router_id:
			# drop the packet
			self.drop_packet(event)
			return
		
		if router_id not in self.topology_database:
			# first time entry
			self.topology_database[router_id] = []
			self.topology_sequence_no[router_id] = -1

		# Drop the packet if it is older than current sequence number
		if sequence_no <= self.topology_sequence_no[router_id]:
			# drop the packet
			self.drop_packet(event)
			return
		
		# Drop the packet if the contents received from this packet is already present in the database
		if not self.check_and_update_database(router_id, neighbors, sequence_no):
			# drop the packet
			self.drop_packet(event)
			return

		# If the code reaches here this implies that we have some changes in our existing database
		# Thus we will recalculate the routing table based on current topology database
		self.recalculate_routing_table()

		# Reduce TTL and Forward the packets to other interfaces 


	def forward_pkt_to_next_hop(self, packet, match, event, route, justSend = False):
		ipp = packet.find("ipv4")
		if ipp.ttl <= 1:
			return self.send_icmp_ttl_exceed(packet, match, event)
	
		nextHopIp = route.nextHopIpAddr if str(route.nextHopIpAddr) not in self.myips else match.nw_dst
		if not justSend and nextHopIp not in self.arpTable:
			self.send_arp_request(event, route, packet, match, nextHopIp)
			q = self.queuedMsgForArp.get(nextHopIp, [])
			q.append([packet, match, event, route])
			self.queuedMsgForArp[nextHopIp] = q
			return
		
		if nextHopIp not in self.arpTable:
			log.info("%s: mac for nexthopip(%s) is not present in arptable(%s). returning"%(self.name, nextHopIp, self.arpTable))
		
		nextHopAddr = self.arpTable[nextHopIp]#ROUTERS_IP_2_PORT[str(route.nextHopIpAddr)] if str(route.nextHopIpAddr) not in self.myips or nextHopIp not in self.arpTable else self.arpTable[nextHopIp]
		
#         ipp.ttl = ipp.ttl - 1
# #         packet_in = event.ofp
#           
#         e = packet#pkt.ethernet()
#         e.src = self.port2Mac[self.intf2Port[route.intf]]
#         e.dst = nextHopAddr
# #         e.type = e.IP_TYPE
#   
# #         e.payload = ipp
#           
#         msg = of.ofp_packet_out()
#         msg.actions.append(of.ofp_action_output(port = self.intf2Port[route.intf]))
#         msg.data = e#vent.ofp
# #         msg.in_port = event.port
#         event.connection.send(msg)
#         return        

		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet, event.port)
		#import pdb; pdb.set_trace()
		log.debug("%s: intf: %s, ,port2Mac: %s, intf2Port: %s, dst: %s", self.name, route.intf, self.port2Mac, self.intf2Port, nextHopAddr)

		#msg.actions.append(action)
		action = of.ofp_action_dl_addr()
		msg.actions.append(action.set_dst(nextHopAddr))
		msg.actions.append(action.set_src(self.port2Mac[self.intf2Port[route.intf]]))
		msg.actions.append(of.ofp_action_output(port = self.intf2Port[route.intf]))
		msg.data = event.ofp
		event.connection.send(msg)


	def send_icmp_msg_large(self, event, src_ip = IP_ANY, dst_ip = IP_ANY, src_mac = ETHER_BROADCAST,
							dst_mac = ETHER_BROADCAST, payload = None, icmp_type = pkt.TYPE_ECHO_REPLY):
		
		icmp = pkt.icmp()
		icmp.type = icmp_type
		icmp.payload = payload

		# Make the IP packet around it
		ipp = pkt.ipv4()
		ipp.protocol = ipp.ICMP_PROTOCOL
		ipp.srcip = src_ip
		ipp.dstip = dst_ip

		e = pkt.ethernet()
		e.src = src_mac
		e.dst = dst_mac
		e.type = e.IP_TYPE

		ipp.payload = icmp
		e.payload = ipp

		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = e.pack()
		msg.in_port = event.port
		event.connection.send(msg)
	
	def send_icmp_ttl_exceed(self, packet, match, event):
		payload = b"    "+packet.find("ipv4").pack()
		return self.send_icmp_msg_large(event, IPAddr(ROUTERS_IPS[self.port2intf[event.port]]), packet.find("ipv4").srcip, packet.dst, packet.src, payload, pkt.TYPE_TIME_EXCEED)

	def send_icmp_msg_small(self, packet, match, event, icmp_type = pkt.TYPE_ECHO_REPLY, payload = None):
		pload = payload if payload is not None or packet is None or packet.find("icmp") is None else packet.find("icmp").payload
		return self.send_icmp_msg_large(event, packet.find("ipv4").dstip, packet.find("ipv4").srcip, packet.dst, packet.src, pload, icmp_type)
		
		icmp = pkt.icmp()
		icmp.type = pkt.TYPE_ECHO_REPLY
		icmp.payload = packet.find("icmp").payload

		# Make the IP packet around it
		ipp = pkt.ipv4()
		ipp.protocol = ipp.ICMP_PROTOCOL
		ipp.srcip = packet.find("ipv4").dstip
		ipp.dstip = packet.find("ipv4").srcip

		e = pkt.ethernet()
		e.src = packet.dst
		e.dst = packet.src
		e.type = e.IP_TYPE

		ipp.payload = icmp
		e.payload = ipp

		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = e.pack()
		msg.in_port = event.port
		event.connection.send(msg)

		log.debug("%s pinged %s", ipp.dstip, ipp.srcip)

#================================
#    All arp business goes below
#================================
	def handle_arp_packet(self, event, packet):
		match = of.ofp_match.from_packet(packet)
		if match.nw_src not in self.arpTable and match.nw_src not in (IP_ANY, IP_BROADCAST) and match.dl_src not in (ETHER_ANY, ETHER_BROADCAST):
			self.arpTable[match.nw_src] = match.dl_src
		if match.nw_dst not in self.arpTable and match.nw_dst not in (IP_ANY, IP_BROADCAST) and match.dl_dst not in (ETHER_ANY, ETHER_BROADCAST):
			self.arpTable[match.nw_dst] = match.dl_dst
			
		if match.nw_proto == pkt.arp.REQUEST:
			log.debug("%s: got rerequest, match: %s"%(self.name, match))
			if match.nw_dst == IPAddr(ROUTERS_IPS[self.port2intf[event.port]]):
				self.send_arp_response(packet, match, event)
			else:
				log.debug("%s: got rerequest and droping it, match: %s"%(self.name, match))
				self.drop_packet(event)
		elif match.nw_proto == pkt.arp.REPLY:
#             import pdb; pdb.set_trace()
			log.debug("%s: got arp response, match: %s"%(self.name, match))
			if match.nw_src in self.outstandingarp:
				for waiting in self.queuedMsgForArp.get(match.nw_src, []):
					#packetN, matchN, event, route = waiting
					self.forward_pkt_to_next_hop(*waiting)
				try:
					del self.queuedMsgForArp[match.nw_src]
					del self.outstandingarp[match.nw_src]
				except Exception, e:
					log.info("%s: problem"%self.name)
			else:
				self.drop_packet(event)  

	def send_arp_response(self, packet, match, event):
		# reply to ARP request
		#import pdb; pdb.set_trace()
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = self.port2Mac[event.port]
		self.arpTable[match.nw_src] = match.dl_src
		e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		log.debug("%s:%i %i answering ARP for %s" % (self.name, event.dpid, event.port, str(r.protosrc)))
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)
		
	def send_arp_request(self, event, route, packet, match, nextHopIp):
		
		if nextHopIp in self.outstandingarp and time.time() > self.outstandingarp[nextHopIp] + self.ARP_TIMEOUT:
			return
		self.outstandingarp[nextHopIp] = time.time()
		r = pkt.arp()
		r.hwtype = r.HW_TYPE_ETHERNET
		r.prototype = r.PROTO_TYPE_IP
		r.hwlen = 6
		r.protolen = r.protolen
		r.opcode = r.REQUEST
		r.hwdst = ETHER_BROADCAST
		
		r.protodst = nextHopIp
		r.hwsrc = self.port2Mac[self.intf2Port[route.intf]]
		r.protosrc = IPAddr(ROUTERS_IPS[route.intf])
		
		#r.protodst = packet.next.dstip
		e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc,
					 dst=r.hwdst)
		e.set_payload(r)
		log.debug("%s ARPing for %s on behalf of %s" % (route.intf, r.protodst, r.protosrc))
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		#msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		msg.actions.append(of.ofp_action_output(port = self.intf2Port[route.intf]))
		msg.in_port = event.port
		event.connection.send(msg)
	
	def send_arp_response(self, packet, match, event):
		# reply to ARP request
		#import pdb; pdb.set_trace()
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = self.port2Mac[event.port]
		self.arpTable[match.nw_src] = match.dl_src
		e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		log.debug("%s:%i %i answering ARP for %s" % (self.name, event.dpid, event.port, str(r.protosrc)))
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	
#     def _handle_QueueStatsReceived(self, e): 
#         log.info("inside QueueStatsReceived") 
#     def _handle_ConnectionDown(self, e): 
#         log.info("inside ConnectionDown") 
#     def _handle_PortStatus(self, e): 
#         log.info("inside PortStatus") 
#     def _handle_PortStatsReceived(self, e): 
#         log.info("inside PortStatsReceived") 
#     def _handle_RawStatsReply(self, e): 
#         log.info("inside RawStatsReply") 
#     def _handle_AggregateFlowStatsReceived(self, e): 
#         log.info("inside AggregateFlowStatsReceived") 
#     def _handle_ConnectionUp(self, e): 
#         log.info("inside ConnectionUp") 
#     def _handle_SwitchDescReceived(self, e): 
#         log.info("inside SwitchDescReceived") 
#     def _handle_FlowStatsReceived(self, e): 
#         log.info("inside FlowStatsReceived") 
#     def _handle_TableStatsReceived(self, e): 
#         log.info("inside TableStatsReceived") 
#     def _handle_ErrorIn(self, e): 
#         log.info("inside ErrorIn") 
#     def _handle_BarrierIn(self, e): 
#         log.info("inside BarrierIn") 
#     def _handle_FlowRemoved(self, e): 
#         log.info("inside FlowRemoved") 
#     def _handle_(self, e): 
#         log.info("inside ") 

class DefHalndler(EventMixin):
	"""
	Waits for OpenFlow switches to connect and makes them learning switches.
	"""
	def __init__ (self, transparent):
		EventMixin.__init__(self)
		self.listenTo(core.openflow)
		self.transparent = transparent

	def _handle_ConnectionUp (self, event):
		log.debug("Connection %s" % (event.connection,))
		RouterHandler(event.connection, transparent=self.transparent)
	#def _handle_PacketIn(self, event):
	#    log.debug("Packet In event in router %s"%self.name)


def launch (transparent=False):
	"""
	Starts an Simple Router Topology
	"""        
	core.registerNew(DefHalndler, str_to_bool(transparent))
	
	#r = get_ip_setting()
	#if r == -1:
	#    log.debug("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
	#    sys.exit(2)
	#else:
	#    log.debug('*** ofhandler: Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
