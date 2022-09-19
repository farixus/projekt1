import nmap
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _worker

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
    END_PORT = 40
    ports = range(START_PORT, END_PORT+1) # zakres portow do skanowania
    
    print("Scanning...")
    sockets = {}
    for ip in ips:
        sockets_to_check = [] # lista gniazd do skanowania format: lista stringow: ip/port
        address = str(ip)
        for port in ports:
            port = str(port)
            sockets_to_check.append(address + "/" + port) # przyklad: 192.168.1.1/21
        # print(sockets_to_check)

        open_ports = []
        with ThreadPoolExecutor() as pool:
            open_sockets = pool.map(socket_state, sockets_to_check)
            # print(open_sockets)
            for open_socket in open_sockets:
                if open_socket:
                    ip, port = open_socket.split("/")
                    open_ports.append(port)
                    print(f'Socket {ip}, {port} is opened')
            sockets[ip] = open_ports
    return sockets

print(scan_hosts(['192.168.10.100']))
