from os import system

class NAT():
	def __init__(self):
		pass
	def enable_forwarding(self):
		system("sysctl -w net.ipv4.ip_forward=1");

	def masquerade_tun_interface(self):
		system("iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE");

	def disable_forwarding(self):
		system("sysctl -w net.ipv4.ip_forward=0");

	def disable_masquerade_tun_interface(self):
		system("iptables -t nat -D POSTROUTING ! -o lo -j MASQUERADE");