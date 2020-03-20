config = {
	"TUN_ADDRESS": "10.0.0.1",
	"TUN_NETMASK": "255.255.255.0",
	"LISTEN_ADDRESS": "0.0.0.0",
	"LISTEN_PORT": 443,
	"TUN_NAME": "tun0",
	"TUN_MTU": 1496, # TUN MTU must be (buffer_size - len(data_header))
	"BUFFER_SIZE": 1500,
	"CERTIFICATE_CHAIN": "./certificates/certchain.pem",
	"PRIVATE_KEY": "./certificates/private.key",
	"SALT": "WH!{*ewP]x}0RHoP9k|nu_L(R9jm*/:i"
}
