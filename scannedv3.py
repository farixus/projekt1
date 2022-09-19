import nmap


def socket_state(socket:str)-> str:
    return_socket = ''
    ip,port = socket.split('/')       
    scanner = nmap.PortScanner()
    resp = scanner.scan(ip, str(port))
    resp = resp['scan'][ip]['tcp'][int(port)]['state'] # nr portu musi byc int
    if resp == "open":
        return_socket = ip+'/'+port
    return return_socket # zwracamy liste otwartych gniazd w formacie ip/port (str)


def scan_hosts(ips: list) -> dict:
    """Gets the list of ip to scan, returns list of opened ports assign to specific ip address
    Uses nmap (need to be imported), method PortScaner().
    Run as root

    Args:
        ips (list): list of ip to scan

    Returns:
        dict: key: ip, value: list of opened ports
    """
    START_PORT = 21
    END_PORT = 30
    ports = range(START_PORT, END_PORT) # zakres portow do skanowania
    sockets_to_check = [] # lista gniazd do skanowania format: lista stringow: ip/port
    print("Scanning...")
    hosts_open_ports = {}
    open_ports = []
    for ip in ips:
        address = str(ip)
        for port in ports:
            port = str(port)
            sockets_to_check.append(address + "/" + port) # przyklad: 192.168.1.1/21

        open_sockets = [] # lista otwartych portow
        open_sockets = map(socket_state, sockets_to_check)
        for open_socket in open_sockets:
            if open_socket:
                ip, port = open_socket.split("/")
                open_ports.append(port)
                print(f'Socket {ip}, {port} is opened')
                # open_sockets.append(open_socket)
        hosts_open_ports[ip] = open_ports
        
    return hosts_open_ports

# tests with scanning. Hosts with adresses below must be active
# warning - port can be filtered (80/http)
print(scan_hosts(['192.168.1.1']))
