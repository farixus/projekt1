import socket


def get_banner(addresses_ports: dict) -> None:
    """Function trying to discover software for opened ports and print it out

    Args:
        addresses_ports (dict): key: ip, value: list of opened ports
    """
    
    for addr_ip, ports_list in addresses_ports.items():
        if len(ports_list) == 0:
            print("Host: {addr_ip} no ports opened")
            continue
        for port in ports_list:
            # print(port)
            try:
                fd = socket.socket() # create socket
                fd.connect((addr_ip, int(port))) #connect to ip/port
                fd.settimeout(2)
                query = "GET / HTTP/1.1\nHost: " + addr_ip + "\n\n" # making query
                fd.send(query.encode()) # send query to server 
                receive = fd.recv(2048).decode() # receive 2048 bytes
                if port == 80:    #if port 80 / http - parsing the answer
                    lines = receive.splitlines()
                    for line in lines:
                        if line.startswith("Server:"):
                            receive = line
              
                print(f"Host:{addr_ip} port:{port} software:{receive}")
            
            except socket.error:
                print(f"Host: {addr_ip} port: {port}")
                print("Socket error", socket.error) # exception in case port is close
            finally:
                fd.close()

# dictionary test
test_sockets = {'192.168.10.100': [21, 22, 80]}
# print(test_sockets)
get_banner(test_sockets)