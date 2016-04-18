from pox.lib.revent import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet import arp, icmp
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST, ETHER_ANY
from pox.lib.addresses import IPAddr, IP_ANY, IP_BROADCAST, EthAddr
from pox.lib.recoco import Timer
# from pox.proto.arp_helper import *
import time


log = None
if core != None:
	log = core.getLogger()

SWITCH_TYPE_INVALID     = 0x00
SWITCH_TYPE_HUB         = 0x01
SWiTCH_TYPE_ROUTER      = 0x02

#TODO: remove this table, and use some file
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
def calc_checksum(msg):
    s = 0
    w = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

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

DEFAULT_PORTS = {
	"R1" : 	"R1-eth1",
	"R3" : "R3-eth2",
	"R2" : "R2-eth3",
	"R4" : "R4-eth3"
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
		if len(txtEntry)==0:
			self.netIP          = None
			self.netMaskCnt     = None
			self.netMask        = None
			self.nextHopIp      = None
			self.intf           = None
			self.nextHopIpAddr  = None
		else:
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
			raise Exception("Invalid entry: Routing entry must have 3 fields")
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


HELLO_INT = 2
LSUINT = 4
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
	def __init__(self, ip=""):

		self.ip = ip2int(ip) # 32-bit IP address of associated interface
		self.mask = ip2int("255.255.255.0") # 32-bit subnet mask of associated interface
		self.helloint = HELLO_INT # 16-bit interval in seconds between HELLO broadcasts
		self.neighbors = {} # neighbors is a dictionary of tuples
		# Each tuple consist of neighbor_id, timestamp

	def add_neighbor(self, neighbor_id, neighbor_ip, timestamp, subnet, net_mask, src_mac):
		print "adding neighbors"
		print neighbor_id
		print timestamp
		print subnet
		print net_mask
		print src_mac
		self.neighbors[neighbor_ip] = Neighbor(neighbor_id, timestamp, subnet, net_mask, src_mac)
		self.neighbors[neighbor_ip].printN()
		print "Done adding"

class Neighbor(object):
	"""docstring for Neighbor"""

	def __init__(self, neighbor_id, timestamp, subnet, net_mask, src_mac):
		print "Creating Neighbor"
		self.neighbor_id = neighbor_id
		self.timestamp = timestamp 
		self.subnet = subnet 
		self.net_mask = net_mask
		self.mac = src_mac
	def printN(self):
		print int2ip(self.neighbor_id)
		# print self.timestamp
		print int2ip(self.subnet)
		print int2ip(self.net_mask)
		print self.mac
		
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
		self.hello_timers = {}


		self.initialize_controller()
		print self.name
		print self.myips
		########### PWOSPF data population
		#self.initialize_pwospf_data()
		self.lsu_timer = None
		self.my_sequence_no = 0

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
			self.initialize_pwospf_data()
			self.set_hello_timers()
			print " --------------- TImer will be set ---------------"
			self.lsu_timer = Timer(timeToWake = LSUINT, callback= self.send_lsu_packet, absoluteTime=False, recurring=True, args=[None, 10])
		self.routingInfo = RoutingTable()
		# if self.name in rtable:
		# 	self.routingInfo = RoutingTable()
		# 	self.routingInfo.addEntries(rtable[self.name])

	def initialize_pwospf_data(self):
		# By default it is the IP of the 0th interface of the router
		self.router_id = ip2int(self.myips[0])
		self.topology_database[self.router_id]=[]
		self.topology_sequence_no[self.router_id]=-1
		
		self.interfaces = {}
		for port_name, port_no in self.intf2Port.iteritems():
			interface = InterfaceData(ROUTERS_IPS[port_name])
	#		interface.ip = ip2int()	
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
		print "----------received a packet ----------"
		if packet.find("arp"):
			self.handle_arp_packet(event, packet)
		elif packet.find("ipv4"):
			self.handle_ipv4_packet(event, packet)
		else:
			self.drop_packet(event)

	def handle_ipv4_packet(self, event, packet):
		print "----------- receiving ipv4 packet ----------------"
		match = of.ofp_match.from_packet(packet)
		rd = self.routingInfo.getMatchedEntry(match.nw_dst)
		rs = self.routingInfo.getMatchedEntry(match.nw_src)
		print "------checking payload -----------"
		if packet.payload.protocol == PWOSPF_PROTOCOL:
			print "------------- PWOSPF ------------"
			self.handle_pwospf_packet(event, packet)

		print self.name + " Handling IPV4 packet with source and destination as"
		print match.nw_src
		print match.nw_dst
		print rs
		print rd
		print "____________________________________________________"

		if match.nw_dst in self.myips:
			log.debug("%s: rs: %s, rs: %s"%(self.name, rs, rd))
			if packet.find("icmp") and packet.find("icmp").type == pkt.TYPE_ECHO_REQUEST:
				self.send_icmp_msg_small(packet, match, event)
		else:
			log.debug("%s: its a ip pkt match: %s"%(self.name, match))
			if rd is not None:
				self.forward_pkt_to_next_hop(packet, match, event, rd, False)
			else:
				self.send_icmp_msg_small(packet, match, event, pkt.TYPE_DEST_UNREACH, packet)
				#self.drop_packet(event)

	def handle_pwospf_packet(self, event, packet):
		print "----- receiving pwospf packet ------------"
		payload = packet.payload.payload
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
		print type(payload)
		(version, pwospf_type, packet_length, router_id, area_id, checksum, 
			autype, auth) = struct.unpack('!BBHIIHHQ', payload[:PWOSPF_MIN_LEN])
		checksum_calculated = calc_checksum(struct.pack('!BBHIIH', version, pwospf_type, packet_length, router_id, area_id, autype))
		if checksum_calculated == checksum:
			log.debug("CHECKSUM PEACE")
		else:
			log.debug("DROP PACKET INCORRECT CHECKSUM")
			self.drop_packet(event)
			return 

		if pwospf_type == PWOSPF_HELLO_TYPE:
			self.handle_hello_packet(event, packet)
		elif pwospf_type == PWOSPF_LSU_TYPE:
			self.handle_lsu_packet(event, packet)
		else:
			log.error("Incorrect type of PWOSPF packet")

	def handle_hello_packet(self, event, packet):
		print " ---- receiving hello packet ---"
		payload = packet.payload.payload
		#print packet.srcip.toUnsigned
		print str(packet.payload.srcip)
		srcip = ip2int(str(packet.payload.srcip))
		dstip = ip2int(str(packet.payload.dstip))
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
			autype, auth, net_mask, helloint, padding) = struct.unpack('!BBHIIHHQIHH',  payload[:HELLO_MIN_LEN])
		subnet = srcip & net_mask

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
		print port_no
		print neighbor_id
		print neighbor_ip
		print timestamp
		self.interfaces[port_no].add_neighbor(neighbor_id, neighbor_ip, timestamp, subnet, net_mask, packet.src)
		if neighbor_id in self.hello_timers:
			print "TImer CANCELLED"
			self.hello_timers[neighbor_id].cancel()	
		print 3*helloint
		print "RECEIVED NEIGHBOR ID BY FROM " + str(int2ip(self.router_id)) + " " +str(int2ip(neighbor_id))
		self.hello_timers[neighbor_id] = Timer(timeToWake = 3*helloint, callback= self.drop_link, absoluteTime=False, recurring=False, args=[neighbor_id, port_no])
		
		print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
		print "Using Hello packet updated neighbors for "+self.name
		for port in self.connection.features.ports:
			if self.name!=port.name:
				print port.name
				print type(self.interfaces[port.port_no])
				print "printing the neighbors"
				for neighbor in self.interfaces[port.port_no].neighbors:
					print self.interfaces[port.port_no].neighbors[neighbor].printN()
				self.interfaces[port.port_no].neighbors
		print "--------------------------------------------------------"

	# the following function sets hello timers and calls send_hello_packet periodically
	def drop_link(self, neighbor_id, port_no):
		print "LINK DROPPED :o"
		print self.topology_database
		del self.topology_database[neighbor_id]
		print self.interfaces[port_no].neighbors
		for port, interface in self.interfaces.iteritems():
			if neighbor_id in interface.neighbors:
				del self.interfaces[port_no].neighbors[neighbor_id]
		print "RECALCULATE WILL BE CALLED DUE TO LINK DROP"
		self.recalculate_routing_table()
		print "LSU PACKETS WILL BE SENT"
		self.send_lsu_packet()
	def set_hello_timers(self):
		# for interfaces of router
		i = 0
		l = len(self.connection.features.ports)
		for port in self.connection.features.ports:
			if i == l-1:
				break
			print port
			i += 1
			Timer(timeToWake = self.interfaces[port.port_no].helloint, callback= self.send_hello_packet, absoluteTime=False, recurring=True, args=[self.interfaces[port.port_no], port])

	def send_hello_packet(self, interface, port):
		""" 
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
	 	print "---------------- Hello packet sending from" + self.name + str(len(interface.neighbors)) + "------------- "  

		
		src_ip = IPAddr(interface.ip)
		
		version = 2
		packet_length = 32 # doubt
		router_id = self.router_id
		area_id = 0
		autype = 0 			
		auth = 0 			
		network_mask = interface.mask
		helloint = interface.helloint
		padding = 0 #doubt
		checksum = calc_checksum(struct.pack('!BBHIIH', version, 1, packet_length, router_id, area_id, autype))
		packet = struct.pack('!BBHIIHHQIHH', version, 1, packet_length, router_id, 
				area_id, checksum, autype, auth, network_mask, helloint, padding)
		# Make the IP packet around it
		ipp = pkt.ipv4()
		ipp.protocol = PWOSPF_PROTOCOL
		ipp.srcip = src_ip
		print src_ip
		ipp.dstip = IPAddr(ALLSPFRouters)
		ipp.payload = packet
		e = pkt.ethernet()
		e.src = self.port2Mac[self.intf2Port[port.name]]
		e.dst = "FF:FF:FF"
		e.type = e.IP_TYPE
		e.payload = ipp
		print "payload set"
		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = port.port_no))
		msg.data = e.pack()
		# msg.in_port = port
		self.connection.send(msg)
		print "sent hello packet"

	def send_lsu_packet(self, without_port=None, ttl=10):
		"""
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                           Subnet                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                           Mask                                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         Router ID                             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		"""
		print "--------------sending lsu packet -----------------------"
		lsu_data = list()
		l = len(self.connection.features.ports)
		i = 0
		temp_list = list()
		for port in self.connection.features.ports:
			if i == l-1:
				break
			i += 1
			for neighbor, neighbor_data in self.interfaces[port.port_no].neighbors.iteritems():
				subnet = neighbor_data.subnet
				net_mask = neighbor_data.net_mask
				router_id = neighbor_data.neighbor_id
				# dest_ip = neighbor
				# dest_id = self.interfaces[port].neighbors[neighbor][0]
				# mask = self.interfaces[port].mask
				# subnet = self.interfaces[port].ip & self.interfaces[port].mask

				lsu_data.append(subnet)
				lsu_data.append(net_mask)
				lsu_data.append(router_id)
				temp_list.append((subnet, net_mask , router_id))

			if(port.name==DEFAULT_PORTS[self.name]):
				mask = self.interfaces[port.port_no].mask
				ip = ROUTERS_IPS[port.name]
				subnet = ip2int(ip) & mask
				router_id = self.router_id
				temp_list.append((subnet, mask, router_id))
				lsu_data.append(subnet)
				lsu_data.append(mask)
				lsu_data.append(router_id)
		    	src_ip = self.interfaces[port.port_no].ip
		self.topology_database[self.router_id] = temp_list
		packet = None
		for port in self.connection.features.ports:
			if port.name == self.name:
				continue
			if without_port == port.port_no:
				print "CHECKHERE HERE " 
				print without_port
				print port.port_no
				continue
			version = 2
			packet_length = 32+len(lsu_data)*4 # doubt
			router_id = self.router_id
			print router_id
			area_id = 0
			autype = 0 			
			auth = 0 			
			network_mask = self.interfaces[port.port_no].mask
			helloint = self.interfaces[port.port_no].helloint
			padding = 0 #doubt
			checksum = calc_checksum(struct.pack('!BBHIIH', version, PWOSPF_LSU_TYPE, packet_length, router_id, area_id, autype))
			packing_string = '!BBHIIHHQHHI'
			# for i in range(0,len(lsu_data)):
			packing_string += (str(len(lsu_data)) + 'I')
			print "LSU Length = " + str(len(lsu_data)) + " length of packing string = " + str(len(packing_string))
			packet = struct.pack(packing_string, version, PWOSPF_LSU_TYPE, packet_length, router_id, area_id, checksum, 
			autype, auth, self.my_sequence_no, ttl, len(lsu_data)/3, *lsu_data)  # TTL = 100
			self.my_sequence_no += 1
			# Make the IP packet around it
			for neighbor in self.interfaces[port.port_no].neighbors:
				ipp = pkt.ipv4()
				ipp.protocol = PWOSPF_PROTOCOL
				ipp.srcip = IPAddr(self.interfaces[port.port_no].ip)
				ipp.dstip = IPAddr(neighbor)
				ipp.payload = packet
				e = pkt.ethernet()
				e.src = EthAddr(self.port2Mac[port.port_no])
				e.dst = EthAddr(self.interfaces[port.port_no].neighbors[neighbor].mac)
				e.type = e.IP_TYPE
				e.payload = ipp
				
				msg = of.ofp_packet_out()
				msg.actions.append(of.ofp_action_output(port = int(port.port_no)))
				msg.data = e.pack()
				#msg.in_port = port #doubt
				print "MSG SENT"
				self.connection.send(msg)

	
	def check_and_update_database(self, router_id, neighbors, sequence_no):
		existing_neighbors = self.topology_database[router_id]
		if not (set(neighbors) ^ set(existing_neighbors)): #symmetric difference
			# no difference found
			print "\n\n\n\n\n"
			print "NO FURTHER UPDATES"
			print "\n\n\n\n\n"

			print len(existing_neighbors)
			return False

		self.topology_database[router_id] = neighbors
		print "Nbrs 2"
		print len(neighbors)
		self.topology_sequence_no[router_id] = sequence_no

		print "Topology Database:"
		print int2ip(self.router_id)
		for id, data in self.topology_database.iteritems():
			print int2ip(id) + " : ",
			for datum in data:
				print int2ip(datum[0]) + " , " \
					+ int2ip(datum[1]) + " , " \
					+ int2ip(datum[2])
		print "\n\n\n\n\n"
		return True

	def get_interface_name_from_router_id(self, router_id):
		# print "\n\n\n\n\n\n"
		# print "Searching router_id = " + int2ip(router_id)
		# print int2ip(self.router_id)
		# for port_no, interface_data in self.interfaces.iteritems():
		# 	print port_no
		# 	for neighbor, value in interface_data.neighbors.iteritems():
		# 		print "neighbor : " + int2ip(neighbor)
		# 		print value.printN()
		# print "\n\n\n\n\n\n"
		if self.router_id == router_id:
			return ip2int(ROUTERS_IPS[DEFAULT_PORTS[self.name]]), DEFAULT_PORTS[self.name]
		for port_no, interface_data in self.interfaces.iteritems():
			for neighbor_ip, value in interface_data.neighbors.iteritems():
				neighbor_id = value.neighbor_id
				if router_id == neighbor_id:
					# print "\n\n\n\n\n\nyoyoyo\n\n\n\n\n\n"
					return neighbor_ip, self.port2intf[port_no]
		return None, None

	def recalculate_routing_table(self):
		# We have to calculate routing table from the topology_database
		# Each element in the queue is a (current node, next hop) tuple
		# We construct node to interface mapping in parallel
		
		new_routing_table = RoutingTable()
		visited, queue = set(), [(self.router_id, None)]
		while queue:
			# print "Inside while "
			vertex_router_id, next_hop = queue.pop(0)
			if vertex_router_id in visited:
				# print "Already Visited "
				continue
			if next_hop == None:
				# this is the root node. All the next hops for its neighbors will be pointed to themselves
				# print "Not Already Visited"
				# print vertex_router_id
				neighbors = self.topology_database[vertex_router_id]
				# print  "Neighbors"
				# print int2ip(self.router_id)
				# for x in neighbors:
				# 	print int2ip(x[0])
				# 	print int2ip(x[1])
				# 	print int2ip(x[2])
				# 	print ""
				for neighbor in neighbors:
					# assign the next_hop as own router_id and push in the queue
					# print "Neighbor " 
					# print neighbor
					subnet, mask, router_id = neighbor
					if router_id in visited:
						continue
					queue.append((router_id, router_id))
					# Create a routing table entry
					next_hop_ip, port_name = self.get_interface_name_from_router_id(router_id)

					if port_name == None:
						# LSU received before HELLO
						# drop this this!
						print "HOLY FUCK"
						print (int2ip(neighbor[0]),int2ip(neighbor[1]),int2ip(neighbor[2])) 
						queue.pop()
						continue
					mask_no = bin(mask).count('1')
					subnet = int2ip(subnet)
					subnet += "/" + str(mask_no)
					print "Identifier"
					print (subnet, int2ip(next_hop_ip), port_name)
					new_routing_table.addEntry([subnet, int2ip(next_hop_ip), port_name])
			else:
				# this is not the root node. All the next hops for its neighbors will be pointed to the current_next_hop
				if vertex_router_id not in self.topology_database:
					continue
				neighbors = self.topology_database[vertex_router_id]
				for neighbor in neighbors:
					# assign the next_hop as current next_hop and push in the queue
					subnet, mask, router_id = neighbor
					if router_id in visited:
						continue
					queue.append((router_id, next_hop))
					# Create a routing table entry
					next_hop_ip, port_name = self.get_interface_name_from_router_id(next_hop)
					mask_no = bin(mask).count('1')
					subnet = int2ip(subnet)
					subnet += "/" + str(mask_no)
					new_routing_table.addEntry([subnet, int2ip(next_hop_ip), port_name])
			visited.add(vertex_router_id)
			# print new_routing_table	
		
		self.routingInfo = new_routing_table
		print self.name + " updating routing table to "
		print self.routingInfo
		
	def handle_lsu_packet(self, event, packet):
		print " --------------------- received LSU packet -----------------"
		payload = packet.payload.payload
		srcip = ip2int(str(packet.payload.srcip))
		dstip = ip2int(str(packet.payload.dstip))
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
		dummy_list = list()
		for i in range(n_advertisements):
			(ad_subnet, ad_mask, ad_router_id) = struct.unpack('!III', advertisements[:ADVERTISEMENT_SIZE])
			neighbors.append((ad_subnet, ad_mask, ad_router_id))
			temp = [ad_subnet, ad_mask, ad_router_id]
			dummy_list = dummy_list + temp
			if i != (n_advertisements-1):
				advertisements = advertisements[ADVERTISEMENT_SIZE:]

		########################## SANITY CHECKS ####################################
		# Drop the packet when the packet received has started from self
		if router_id == self.router_id:
			# drop the packet
			self.drop_packet(event)
			print "My router id found"
			return
		
		if router_id not in self.topology_database:
			# first time entry
			print "Router Id not in database"
			print router_id
			self.topology_database[router_id] = []
			self.topology_sequence_no[router_id] = -1
			print self.topology_database

		# Drop the packet if it is older than current sequence number
		if sequence_no <= self.topology_sequence_no[router_id]:
			# drop the packet
			self.drop_packet(event)
			return
		
		# Drop the packet if the contents received from this packet is already present in the database
		if not self.check_and_update_database(router_id, neighbors, sequence_no):
			# drop the packet
			print "LSU Dropping this packet"
			self.drop_packet(event)
			return

		# If the code reaches here this implies that we have some changes in our existing database
		# Thus we will recalculate the routing table based on current topology database
		self.recalculate_routing_table()

		# Reduce TTL and Forward the packets to other interfaces 
		if ttl>0:
			ttl = ttl -1
			print "FORWARDING THE LSU PACKET TO DIFFERNET NEIGHBORS "
			for port in self.connection.features.ports:
				if port.name  == self.name or port == event.port:
					continue
				#checksum = calc_checksum(struct.pack('!BBHIIH', version, PWOSPF_LSU_TYPE, packet_length, router_id, area_id, autype))
				
				packing_string = '!BBHIIHHQHHI'
				packing_string += (str(3*n_advertisements) + 'I')
				#print "LSU Length = " + str(len(lsu_data)) + " length of packing string = " + str(len(packing_string))
				packet = struct.pack(packing_string, version, PWOSPF_LSU_TYPE, packet_length, router_id, area_id, checksum, 
				autype, auth, sequence_no, ttl, n_advertisements, *dummy_list)  # TTL = 100
				
				# Make the IP packet around it
				for neighbor in self.interfaces[port.port_no].neighbors:
					ipp = pkt.ipv4()
					ipp.protocol = PWOSPF_PROTOCOL
					ipp.srcip = IPAddr(self.interfaces[port.port_no].ip)
					ipp.dstip = IPAddr(neighbor)
					ipp.payload = packet
					e = pkt.ethernet()
					e.src = EthAddr(self.port2Mac[port.port_no])
					e.dst = EthAddr(self.interfaces[port.port_no].neighbors[neighbor].mac)
					e.type = e.IP_TYPE
					e.payload = ipp
					
					msg = of.ofp_packet_out()
					msg.actions.append(of.ofp_action_output(port = int(port.port_no)))
					msg.data = e.pack()
					#msg.in_port = port #doubt
					print "MSG SENT"
					self.connection.send(msg)




	def forward_pkt_to_next_hop(self, packet, match, event, route, justSend = False):
		ipp = packet.find("ipv4")
		if ipp.ttl <= 1:
			return self.send_icmp_ttl_exceed(packet, match, event)
		nextHopIp = route.nextHopIpAddr if str(route.nextHopIpAddr) not in self.myips else match.nw_dst
		# new_route = RoutingEntry()
		# new_route.netIP = route.netIP
		# new_route.netMaskCnt = route.netMaskCnt
		# new_route.netMask = route.netMask
		# print type(nw_dst)
		# print nw_dst
		# print str(nw_dst)
		# print type(ip2int(str(nw_dst)))
		# print ip2int(str)
	 	# print ip2int(nw_dst)

		# new_route.nextHopIp = ip2int(str(nw_dst))
		# new_route.intf = route.intf
		# new_route.nextHopIpAddr = IPAddr(new_route.textedIP(new_route.nextHopIp))
		# new_route.netIP &= new_route.netMask
		# self.netIP          = self.parseTextIp(txtEntry[0])
		# self.netMaskCnt     = self.parseTextMaskCnt(txtEntry[0])
		# self.netMask        = self.parseTextMask(txtEntry[0])
		# self.nextHopIp      = self.parseTextIp(txtEntry[1])
		# self.intf           = txtEntry[2]
		# self.nextHopIpAddr  = IPAddr(self.textedIP(self.nextHopIp))
		# self.netIP         &= self.netMask
		# if nextHopIp=="0.0.0.0":
		# 	nextHopIp = nw_dst
		# 	route = new_route

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
		print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
		print self.name + " handling arp packet"
		print match.nw_dst
		print match.nw_src
		print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
		
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
