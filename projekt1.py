# Projekt 1: Linux + Python

# import functions from separated files. File names must be identical as names in section `from`
from getParameters import get_local_ip_param
from hosts2scan import hosts_alive_list, hosts_list
from scanned import scan_hosts
from bannerGrabbing import get_banner
from bruteForce import brute_force


def main():
    #1,2. get local ip and netmask address using ifcfg module def from getParameters.py
    local_ip_mask = get_local_ip_param('eth0', netmask=True)
    print("1/2. Local ip addres:", local_ip_mask[0], "mask:", local_ip_mask[1])
    print("")

    # 3. list of all hosts in local network to scan without current machine ip using module ipaddress def from host2scan.py
    # hosts = hosts_list(local_ip_mask)
    # print(hosts)

    # 3. list of active hosts in local network without current machine ip using module ipaddress def from host2scan.py
    live_hosts = hosts_alive_list(local_ip_mask)
    print("3. List of active hosts in network:")
    for ip in live_hosts:
        print(ip)

    # 4. list of opened port for actve IPs using nmap.PortScanner() def from scanned.py
    print("4.", end=" ")
    result = scan_hosts(live_hosts) # returns dict key: ip, value: list of ports
    # for ip, ports in result.items():
    #     print(f"ip: {ip:16} {ports}")
    
    # 5. discover software on opned ports (banner grabbing) using module: socket def from bannerGrabbing
    print("5.", end=" ")
    get_banner(result)

    # 6. Trying to force login to server on ports 21 () and 22 () using paramiko (22) i ftplib (21) def from bruteForce.py
    print("6.", end='')
    brute_force(result)
    



if __name__== '__main__':
    main()