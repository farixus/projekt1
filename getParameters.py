import ifcfg

# ifcfg.interfaces() - dictionary: key - if name, value: another dictionary, where:
# key: inet, inet4, ether, inet6, netmask, netmasks, broadcast, broadcasts, prefixlens, device, flags, mtu
# values: values for above parameteres if interface exists
#
# ifcfg.default_interface() - prints parameters of default interface. eth0

# https://pypi.org/project/ifcfg/


def get_local_ip_param(ifname: str, inet=True, inet4=False, ether=False, inet6=False, netmask=False, 
	netmasks=False, broadcast=False, broadcasts=False, prefixlens=False, device=False,flags = False, mtu=False ):
	"""Gets specific ip parameters of specific network device

	Args:
		ifname (str): interface name
		inet (bool, optional): ip address. Defaults to True.
		inet4 (bool, optional): ip4 address as list. Defaults to False.
		ether (bool, optional): ethernet address. Defaults to False.
		inet6 (bool, optional): ip6 address as list. Defaults to False.
		netmask (bool, optional): netmask. Defaults to False.
		netmasks (bool, optional): netmask as list. Defaults to False.
		broadcast (bool, optional): broadcast address. Defaults to False.
		broadcasts (bool, optional): broadcast address as list. Defaults to False.
		prefixlens (bool, optional): prefixlen. Defaults to False.
		device (bool, optional): device name. Defaults to False.
		flags (bool, optional): interface status. Defaults to False.
		mtu (bool, optional): mtu value. Defaults to False.

	Returns:
		list: list of network parameters if value = True
	"""
	parameters = []
	for name, interface in ifcfg.interfaces().items():
		if name == ifname:
			for key, value in interface.items():
				if inet and key == 'inet':
					parameters.append(value)
				elif inet4 and key == 'inet4':
					parameters.append(value)
				elif ether and key == 'ether':
					parameters.append(value)
				elif inet6 and key == 'inet6': 
					parameters.append(value)
				elif netmask and key == 'netmask':
					parameters.append(value)
				elif netmasks and key == 'netmasks':
					parameters.append(value)
				elif broadcast and key == 'broadcast':
					parameters.append(value)
				elif broadcasts and key == 'broadcasts':
					parameters.append(value)
				elif prefixlens and key == 'prefixlens':
					parameters.append(value)
				elif device and key == 'device':
					parameters.append(value)
				elif flags and key == 'flags':
					parameters.append(value)
				elif mtu and key == 'mtu':
					parameters.append(value)
				else:
					pass
		else:
			pass			
	return parameters


# print(ifcfg.interfaces())

# ip = get_local_ip_param('eth0', netmask=True)
# print(ip)


