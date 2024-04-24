from binascii import hexlify

class Utils():
	
	"""
	Convert IP to integer
	"""
	@staticmethod
	def ip_to_int(ip):
		ip_i = 0;
		ip = ip.split(".");
		ip = [int(x) for x in ip];
		l = len(ip);
		i = 0;
		for p in ip:
			ip_i += (p << (8*(l - i - 1)))
			i += 1;
		return ip_i

	"""
	Converts integer to IP
	"""
	@staticmethod
	def int_to_ip(ip):
		return str((ip >> 24) & 0xFF) + "." + str((ip >> 16) & 0xFF) + "." + str((ip >> 8) & 0xFF) + "." + str(ip & 0xFF);

	"""
	Checks if the buffer is empty
	"""
	@staticmethod
	def check_buffer_is_empty(buf):
		if buf == None or buf == None:
			return True;

		if not isinstance(buf, bytearray) and not isinstance(buf, bytes):
			return True;

		if len(buf) == 0:
			return True;

		return False;
	@staticmethod
	def get_destination(buf):
		print(hexlify(buf))
		ip = buf[20:24]
		return Utils.int_to_ip(ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3])

"""
print(Utils.ip_to_int("192.168.0.1"));
print(Utils.int_to_ip(Utils.ip_to_int("192.168.0.1")));
"""
