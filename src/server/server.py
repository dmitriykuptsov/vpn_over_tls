# Network stuff
import socket
import ssl

# Add current directory to Python path
import sys
import os
sys.path.append(os.getcwd())

# Structures
import struct

# Common helpers
from common import packet
from common import database
from common import state
from common import pool
from common import tun
from common import utils
from common import tun
from common import dns
from common import routing
from common import nat

# Threading
import threading

# Configuration
import config
# Security functions
from hashlib import sha256

# Timing 
from time import sleep

# Exit hook
import atexit

class Server():

	"""
	Initializes the server
	"""
	def __init__(self, config, database):
		"""
		Initialize the database
		"""
		self.database = database;

		"""
		Initialize state machine
		"""
		#self.sm = state.StateMachine();

		"""
		Initialize IP address pool
		"""

		self.ip_pool = pool.IpPool(config["TUN_ADDRESS"], config["TUN_NETMASK"]);

		"""
		Server configuration 
		"""

		self.hostname = config["LISTEN_ADDRESS"];
		self.port = config["LISTEN_PORT"];
		self.tun_address = config["TUN_ADDRESS"];
		self.tun_name = config["TUN_NAME"];
		self.tun_netmask = config["TUN_NETMASK"];
		self.tun_mtu = config["TUN_MTU"];
		self.buffer_size = config["BUFFER_SIZE"];
		self.salt = config["SALT"];

		"""
		Create secure socket and bind it to address and port
		"""

		self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2);
		self.ctx.load_cert_chain(config["CERTIFICATE_CHAIN"], config["PRIVATE_KEY"]);
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
		self.sock.bind((self.hostname, self.port));
		self.sock.listen(5);
		self.secure_sock = self.ctx.wrap_socket(self.sock, server_side=True);

		"""
		Create tun interface
		"""
		self.tun = tun.Tun(self.tun_name, self.tun_address, self.tun_netmask, self.tun_mtu);

		"""
		Configure NATing
		"""
		self.nat_ = nat.NAT();
		self.nat_.enable_forwarding();
		self.nat_.masquerade_tun_interface();
		"""
		Initialize secure socket buffer
		"""
		self.addr_to_sock_mapping = {};
		self.sock_to_addr_mapping = {};
		self.buffers = {};
	
		tls_thread = threading.Thread(target = self.tls_loop);
		tls_thread.daemon = True;
		tls_thread.start();

	"""
	Writes data to TUN interface
	"""
	def write_to_tun(self, payload):
		if not payload:
			return;
		self.tun.write(bytes(bytearray(payload)));

	"""
	Writes data packet into secure socket
	"""
	def write_to_secure_socket(self, sock, payload):
		if not payload:
			return;
		userdata = packet.DataPacket();
		userdata.set_payload(payload);
		try:
			sock.send(userdata.get_buffer());
		except:
			pass

	"""
	Reads data from secure socket
	"""
	def read_from_secure_socket(self, sock, secure_socket_buffer):
		buf = sock.recv(self.buffer_size);
		print(list(bytearray(buf)))
		print("GOT DATA ON TLS SOCKET " + str(len(buf)))
		if len(buf) == 0:
			raise Exception("Socket was closed");
		secure_socket_buffer += buf;
		print("++++++")
		print(len(secure_socket_buffer))
		if len(secure_socket_buffer) <= packet.Packet.get_header_length():
			return None;
		print(packet.Packet.get_header_length())
		print("----------")
		packet_length = packet.Packet.get_total_length(secure_socket_buffer);
		print(packet_length)
		print("----------")
		if packet_length > len(secure_socket_buffer):
			return None;
		buf = secure_socket_buffer[:packet_length];
		secure_socket_buffer = secure_socket_buffer[packet_length:];
		userdata = packet.DataPacket(buf);
		if userdata.get_type() != packet.PACKET_TYPE_DATA:
			return None;
		print("SENDING DATA TO TUN INTERFACE");
		print(list(bytearray(userdata.get_payload())))
		return userdata.get_payload(), secure_socket_buffer

	"""
	Reads data from TUN interface
	"""
	def read_from_tun(self):
		buf = self.tun.read(self.tun_mtu);
		return buf;
	
	"""
	TUN read loop
	"""
	def tun_loop(self, sock, sm, client_ip):
		secure_socket_buffer = []
		while True:
			try:
				payload, buf = self.read_from_secure_socket(sock, secure_socket_buffer)
				self.write_to_tun(payload)
				secure_socket_buffer = buf
			except Exception as e:
				print(e)
				print("Connection was closed tun_loop");
				sm.unknown();
				self.ip_pool.release_ip(client_ip);
				break;

	"""
	TLS loop
	"""
	def tls_loop(self):
		while True:
			try:
				print("Reading from TUN")
				buf = self.read_from_tun()
				print("Got data on tun interface")
				print(buf)
				dest_addr = utils.Utils.get_destination(buf)
				sock = self.addr_to_sock_mapping.get(dest_addr, None)
				print(dest_addr)
				if not sock:
					continue
				print("sending data to " + dest_addr)
				self.write_to_secure_socket(sock, buf);
			except Exception as e:
				print(e)
				print("Connection was closed in TLS loop")
				#self.ip_pool.release_ip(self.client_ip);
				#break;
	
	def client_loop(self, sock, sm):
		"""
		CLients main loop
		"""
		sm.connected();
		client_ip = None
		while True:
			if sm.is_unknown():
				print("Closing connection to client")
				if client_ip != None:
					self.ip_pool.release_ip(client_ip);
				break;
			elif sm.is_connected():
				buf = None
				try:
					buf = bytearray(sock.recv(self.buffer_size));
					if len(buf) == 0:
						raise Exception("Socket was closed");
				except:
					print("Failed to read from socket...");
					sock.close();
					break;
				if len(buf) > 0:
					print("Received authentication packet...");
					p = packet.AuthenticationPacket(buf);
					try:
						if p.get_type() != packet.PACKET_TYPE_AUTHENTICATION:
							continue;
						if utils.Utils.check_buffer_is_empty(p.get_password()):
							print("Invalid credentials");
							try:
								nack = packet.NegativeAcknowledgementPacket();
								sock.send(nack.get_buffer());
								sock.close();
							except:
								print("Failed to write into socket...");
							break;
						if utils.Utils.check_buffer_is_empty(p.get_username()):
							print("Invalid credentials");
							try:
								nack = packet.NegativeAcknowledgementPacket();
								sock.send(nack.get_buffer());
								sock.close();
							except:
								print("Failed to write into socket...");
							break;
						if self.database.is_authentic(p.get_username(), p.get_password(), self.salt):
							sm.authenticated();
							try:
								ack = packet.AcknowledgementPacket();
								sock.send(ack.get_buffer());
							except:
								print("Failed to write data into socket...");
								break
						else:
							try:
								nack = packet.NegativeAcknowledgementPacket();
								sock.send(nack.get_buffer());
								sock.close();
							except:
								print("Failed to write into socket...");
							break
					except:
						sock.close();
						print("Could not parse data");
						break
			elif sm.is_authenticated():
				client_ip = self.ip_pool.lease_ip();
				configuration = packet.ConfigurationPacket();
				configuration.set_netmask(list(bytearray(self.tun_netmask, encoding="ASCII")));
				configuration.set_default_gw(list(bytearray(self.tun_address, encoding="ASCII")));
				configuration.set_ipv4_address(list(bytearray(client_ip, encoding="ASCII")));
				configuration.set_mtu(list(struct.pack("I", self.tun_mtu)));
				self.sock_to_addr_mapping[sock] = client_ip
				self.addr_to_sock_mapping[client_ip] = sock
				print("Sending configuration data to client " + client_ip)
				try:
					sock.send(configuration.get_buffer());
					sm.configured();
				except:
					print("Failed to write into socket...");
					break;
			elif sm.is_configured():
				tun_thread = threading.Thread(target = self.tun_loop, args=(sock, sm, client_ip));
				#tls_thread = threading.Thread(target = self.tls_loop);
				tun_thread.daemon = True;
				#tls_thread.daemon = True;
				tun_thread.start();
				#tls_thread.start();
				sm.running();
			elif sm.is_running():
				sleep(10);
	"""
	Main loop
	"""
	def loop(self):
		while True:
			(sock, addr) = self.secure_sock.accept();
			sm = state.StateMachine();
			client_thread = threading.Thread(target = self.client_loop, args=(sock, sm));
			#tun_thread.daemon = True;
			client_thread.daemon = True;
			#self.tun_thread.start();
			client_thread.start();
			

	def exit_handler(self):
		self.nat_.disable_forwarding();
		self.nat_.disable_masquerade_tun_interface();

# Start the server
from config import config
server = Server(config, database.FileDatabase("./server/database.dat"));
atexit.register(server.exit_handler);
server.loop();
