import ipaddress


def hosts_list(ip_param: list):
    """Gets parameters of host network device and calculate list to of all possible adresses in local network

    Args:
        ip_param (list): Expected: [ip_addr, netmask]

    Returns:
        list: All possible ip addresses in local network
    """
    host_ip = ip_param[0]
    netmask = ip_param[1]
    network_mask = ipaddress.IPv4Network(host_ip + '/' + netmask, strict=False) # returns ie: 192.168.10.0/24
    hosts = [] # hosts list to return without local machine ip
    
    for host in list(ipaddress.ip_network(network_mask).hosts()):
        if host != ipaddress.IPv4Address(host_ip):
            hosts.append(host)
  
    return hosts

# https://www.thepythoncode.com/article/building-network-scanner-using-scapy

def hosts_alive_list(ip_param: list):
    """Gets parameteres of host network device and calculate list of alive hosts in local network

    Args:
        ip_param (list): Expected: [ip_addr, netmask]

    Returns:
        list: list of alive hosts
    """
    from scapy.all import ARP, Ether, srp
    from netaddr import IPAddress
    target_ip = ip_param[0]+'/'+ str(IPAddress(ip_param[1]).netmask_bits()) # convert mask into bits
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet - ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    packet = ether/arp # stack them
    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip address to `clients` list
        live_received = received.psrc
        if live_received != ip_param[0]: # remove local ip address
            clients.append(live_received)

    return clients


# different adresses and masks tests
# ip_list = hosts_list(['192.168.10.101', '255.255.255.248'])
# print(ip_list)
ip_alive = hosts_alive_list(['192.168.10.100', '255.255.255.0'])
print(ip_alive)


