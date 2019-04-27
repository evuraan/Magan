#!/usr/bin/python3 -u

"""
 * ----------------------------------------------------------------------------
    magan : a DoH server
    Copyright (C) 2019  Evuraan, <evuraan@gmail.com> 

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * ----------------------------------------------------------------------------
"""

import socket
from select import select
from scapy.all import *
import time
import threading
import requests
import struct
import sys

#import logging
#logging.basicConfig(level=logging.DEBUG)


Version = "Magan/1.2.8py"


port = 53
backlog = 100
moo = {}
myReq = requests.Session()
myReq.headers.update({'User-Agent': Version})

# maximum entries allowed in our cache
cache_max_size = 1000 

	
class handle_dns():
	def __init__(self, _payload,proto,socket):
		self.socket = socket
		self._payload = _payload
		self.protocol = proto.lower()
		self.requestor_ip = self._payload[1][0]
		self.requestor_port = self._payload[1][1]
		#print("self.requestor_ip is", self.requestor_ip)
		#print("self.requestor_port is", self.requestor_port)
		print("Request from",self._payload[1], "Protocol:", self.protocol)
		try:
			self.a = DNS(self._payload[0])
			self.id = self.a.id
			self.output = dict()
			self.type = self.a[DNS].qd.qtype
			self.opcode = self.a.opcode
			self.qname = self.a[DNS].qd.qname
			self.qtype = self.a[DNS].qd.qtype
			self.qclass = self.a[DNS].qd.qclass
			self.key = self.qname.decode("utf-8") + "&type=" + str(self.type)
			self.url = "https://dns.google.com/resolve?name=" + self.key
			#self.url = "http://192.168.1.1:9194/resolve?name=" + self.key
			self.IP = IP(dst=self.requestor_ip)
			print(self.url)
			if len ( self.key.split(".") ) <= 2:
				# Those single item lookups, likely a local lookup. 
				# let .77 handle this..
				self.send_refuse()
				return 
				#raise NameError('HiThere')
			if not self.use_cache():
				t = threading.Thread(target=self.get_data_from_google)
				t.start()
		except:
			print("Failed to parse incoming DNS data!")
			self.a = False
			return 


	def get_dns_data(self):
		try:
			a = myReq.get(self.url, timeout=8)
			return a
		except:
			return False

	def get_data_from_google(self):
		#print(moo["name"] 
		a = self.get_dns_data()
		if not a:
			self.send_SERVFAIL()
			return None
		
		if a.ok:
			self.gdata = a.json()
		if self.gdata['Status'] == 0:
			self.GOO = True
		else:
			print("Got no response!!!")
			self.GOO = False
			self.ancount = 0 
			self.DNS = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode='name-error', qdcount=1, ancount=self.ancount, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), )
			#send(self.IP / self.UDP / self.DNS )
			#return None
			self.send_return()
		if "Answer" not in self.gdata:
			print("ancount  is 0")
			self.ancount = 0 
			self.DNS = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=self.ancount, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), )
		else:
			self.ancount = len(self.gdata['Answer'])
			zero_data = self.gdata['Answer'][0]
			zero_type = zero_data['type']
			#if zero_type == 15 or zero_type == 6:
			if zero_type  == 6:
				self.soa = encode_soa(self.gdata['Answer'][0]['data']) 
				self.ancount = 1 
				self.DNS = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=self.ancount, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), an=DNSRR(rrname=zero_data['name'],ttl= zero_data['TTL'], type= zero_type,rdata=self.soa ), )
				self.send_return()
				return None
		
				#rdata = '\x00\n\x0cmxb-000c6b02\x04gslb\x08pphosted\x03com\x00'
				_temp = sr1(IP( dst="9.9.9.9")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=self.qname,qtype="MX"))) 
				self.DNS = _temp[DNS]
				self.DNS.id = self.id
				self.send_return()
				#send( self.IP / self.UDP / _temp[DNS])
				return None
			else:
				rdata = zero_data['data'] 
				if zero_type == 15:
					shoo = rdata
					rdata = encode_mx_rdata(shoo.split(" ")[1], shoo.split(" ")[0] )
				elif zero_type == 16:
					shoo = rdata.replace('"','')
					rdata = list()
					rdata.append(shoo.encode("utf-8") )

			self.DNS = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=self.ancount, nscount=0, arcount=0,qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass),  an=DNSRR(rrname=zero_data['name'],ttl= zero_data['TTL'], type= zero_type,rdata=rdata ), )
			if self.ancount > 1:
				for i in range(1, self.ancount ):
					this_data = self.gdata['Answer'][i]
					this_type = this_data['type']
					if this_type == 15:
						#this_rdata = '\x00\n\x0cmxb-000c6b02\x04gslb\x08pphosted\x03com\x00'
						shoo = this_data['data']
						this_rdata = encode_mx_rdata(shoo.split(" ")[1], shoo.split(" ")[0] )
						self.DNS.an.add_payload(DNSRR(rrname=this_data['name'],ttl=this_data['TTL'], type=this_type, rdata=this_rdata))
					elif this_type == 16:
						shoo = this_data['data'].replace('"','')
						this_rdata = list()
						this_rdata.append( shoo.encode("utf-8") )
						self.DNS.an.add_payload(DNSRR(rrname=this_data['name'],ttl=this_data['TTL'], type=this_type, rdata=this_rdata))
					elif this_type == 6:
						shoo = this_data['data']
						this_rdata = encode_soa(shoo)
						self.DNS.an.add_payload(DNSRR(rrname=this_data['name'],ttl=this_data['TTL'], type=this_type, rdata=this_rdata))
						
					else:
						#import pdb; pdb.set_trace()
						this_rdata = this_data['data']
						self.DNS.an.add_payload(DNSRR(rrname=this_data['name'],ttl=this_data['TTL'], type=this_type, rdata=this_rdata))

					#print('this_rdata', this_rdata)
		self.DNS.show()
		self.send_return()
		#send(self.IP / self.UDP / self.DNS )
		#return None

	def send_tc(self):
		# note: this cannot be tcp 
		truncate_reply = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=1, rd=1, ra=1, z=0, ad=0, cd=0, rcode=4, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), )
		try:
			print("Sending TC reply")
			self.socket.sendto(bytes(truncate_reply), self._payload[1])
		except:
			pass
		return None
	
	def send_refuse(self):
		reply = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=5, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), )
		send_this = bytes(reply)
		if self.protocol == "tcp":
			two = struct.pack("!h", len(send_this) )
			send_this = two + send_this
		try:
			self.socket.sendto(send_this, self._payload[1])
		except:
			pass
		return None
		
	def send_SERVFAIL(self):
		reply = DNS(id=self.a.id, qr=1, opcode=self.opcode, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=5, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=self.qname, qtype=self.qtype, qclass=self.qclass), )
		send_this = bytes(reply)
		if self.protocol == "tcp":
			two = struct.pack("!h", len(send_this) )
			send_this = two + send_this
		try:
			self.socket.sendto(send_this, self._payload[1])
		except:
			pass
		return None
			
	def send_return(self):

		# save self.DNS to moo anyway:
		if self.key not in moo:
			moo[self.key] = (self.DNS, time.time() )

		_size = len(self.DNS)
		if _size >= 512 and self.protocol == "udp":
			self.send_tc()
		elif self.protocol == "udp":
			try:
				self.socket.sendto(bytes(self.DNS), self._payload[1])
			except:
				print("That failed!")
				pass
		elif self.protocol == "tcp":
			two = struct.pack("!h", len(self.DNS) )
			send_this = two + bytes(self.DNS) 
			#print("Send_this is", send_this)
			self.socket.sendto(send_this, self._payload[1])

		if self.ancount == 0:
			print(" -- not caching zero ancount for", self.key)
			return None 

		return None

	def use_cache(self):
		if self.key not in moo:
			print("No cache entry for", self.key)
			return False
		# do we have ttl in it?
		try:
			ttl = moo[self.key][0].an.ttl 
			print("ttl is", ttl)
			age = int(time.time() - moo[self.key][1])
			print("Cache Age:", age)
			print("age=", age, "moo[self.key][0].an.ttl=", moo[self.key][0].an.ttl)
			if ( age < moo[self.key][0].an.ttl ):
				print("Cache hit for", self.key)
				new_ttl = ttl - age
				print("Adjusting TTL: {ttl} to {new_ttl}".format(ttl=ttl, new_ttl=new_ttl) )
				we_have = moo[self.key][0]
				we_have.an.ttl = new_ttl
			else:
				# Stale cache, delete key from dict
				print("Stale dict, cleaning key", self.key)
				try:
					del moo[self.key]
				except:
					print("Some crappy error when cleaning key")
				return False
		except:
			we_have = moo[self.key][0]
		if we_have:
			#print("we have!!!!!", moo)
			we_have.id = self.id
			try:
				# to avoid expedited cache expiry
				#self.socket.sendto(bytes(truncate_reply), self._payload[1])
				if self.protocol == "udp":
					self.socket.sendto(bytes(we_have), self._payload[1])
				else:
					two = struct.pack("!h", len(we_have) )
					#send_this = bytes(we_have) +  two
					send_this = two + bytes(we_have)
					#print("Send_this is", send_this)
					self.socket.sendto(send_this, self._payload[1])

				#send(self.IP/ self.UDP / we_have)
				len_moo = len(moo) 
				#print(time.ctime(),"Cache length:", len_moo )
				#print("Snooping on cache data:", moo[self.key])
				if len_moo >= cache_max_size:
					try:
						print( time.ctime(), "Trimming cache")
						moo.popitem()
					except:
						print( time.ctime(), "Failed to trim cache") 
				return True
			except:
				return False
		else:
			return False

def trim_cache(moo):
	threshold = 23000
	if len(moo) >= threshold:
		print( time.ctime(), "Trimming moo")
		moo = {}

		
def old_encode_mx_rdata(input, MX=10):
	global lengths
	MX = int(MX)
	if MX in lengths:
		mx_shit = "\x00" + lengths[MX]
	else:
		mx_shit = "\x00" + lengths[random.choice(list(lengths))]
	if not mx_shit:
		return False
	b = ""
	a = input.split(".")
	for i in a:
		long = lengths[len(i)]
		b += long + i
	if not b:
		return False
	return(mx_shit + b)

def encode_soa(soa):
	SOA = soa.split(" ")
	MNAME = encode_label(SOA[0]).encode()
	RNAME = encode_label(SOA[1]).encode()
	SERIAL = struct.pack("!I", int(SOA[2]))
	REFRESH =  struct.pack("!I", int(SOA[3]))
	RETRY = struct.pack("!I", int(SOA[4]))
	EXPIRE = struct.pack("!I", int(SOA[5]))
	MINIMUM = struct.pack("!I", int(SOA[6]))

	if SOA and MNAME and RNAME and SERIAL and REFRESH and RETRY and EXPIRE and MINIMUM:
		soa_record = MNAME + RNAME + SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM
		return soa_record
	else:
		return False
	return False
	
	

def encode_label(_label):
	b = ""
	for i in _label.split("."):
		b += struct.pack("h", len(i) ).decode().rstrip("\x00") + i
	if b:
		return(b + "\x00")
	else: 
		return False
	
def encode_mx_rdata(MXHOST, MX=10):
	_start = struct.pack("!h", int(MX) ).decode()
	b = encode_label(MXHOST)
	if b:
		return(_start + b)
	else:
		return False



def read_udp(s):
	we_got = s.recvfrom(4096) # data,addr
	print(time.ctime(),"UDP",we_got)
	a = handle_dns(we_got,"udp",s)

def read_tcp(s):
	client, addr = s.accept()
	we_got = client.recv(1024)
	print("We got", we_got)
	a = (we_got[2:], addr)
	b = handle_dns(a,"tcp",client)
	
def old_read_tcp(s):
	client,addr = s.accept()
	data = client.recv(8000)
	print("data is", data)
	dns = DNS(data)
	dns.show()
	print(dns.id)
	print("incoming tcp DNS stuff", dns[DNS])
	#a = handle_dns(data, "tcp", s)
	import pdb; pdb.set_trace()

def show_help():
	print("Usage:")
	print("  -h  --help         print this usage and exit")
	print("  -p  --port         alternate port to listen")
	print("  -v  --version      print version information and exit")
		
	
if __name__ == '__main__':

	if len(sys.argv) >= 2:
		for i in sys.argv:
			if ("help" in i) or (i == "h") or (i == "--h") or (i == "-h")  or ( i == "?" ):
				show_help()
				sys.exit(0)
			if ("version" in i) or (i == "v") or (i == "--v") or (i == "-v"):
				print("Version:", Version)
				sys.exit(0)
			if ("port" in i) or (i == "p") or (i == "--p") or (i == "-p"):
				next = sys.argv.index(i) + 1
				if len(sys.argv) > next:
					newport = sys.argv[next]
					if newport.isdigit():
						print("Using",newport,"as port")
						port = int(newport)
					else:
						print("Invalid usage, bad port")
						show_help()
						sys.exit(1)
				else:
					print("Invalid usage")
					show_help()
					sys.exit(1)
	
	udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp.bind(("", port))
	
	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp.bind(("", port))
	tcp.listen(backlog)

	print(Version, "Copyright (C) 2019 Evuraan <evuraan@gmail.com>")
	print("This program comes with ABSOLUTELY NO WARRANTY.")


	input = [udp, tcp]
	
	while True:
		inputready,outputready,exceptready = select(input,[],[])
		for s in inputready:
			if s == tcp:
				#print("got tcp")
				read_tcp(s)
			elif s == udp:
				#print("got udp!")
				read_udp(s)
			else:
				print("Unknown socket")
				

