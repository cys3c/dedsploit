import os, sys
from time import sleep

if not os.geteuid() == 0:
    sys.exit("\033[1;31mPlease run this script as root!\033[0m")

header = """

  ______________________
< dedsploit installer!!! >
  ----------------------
         \   ^__^
          \  (oo)\_______
             (__)\       )\/\
                 ||----w |
                 ||     ||

"""

print header
print "\033[1;36mOperating Systems Available:\033[1;36m "
print "===================================="
print "(1) Kali Linux / Ubuntu "
print "===================================="

option = input("\033[36m[>] Select Operating System: \033[0m")

if option == 1:
    print "\033[1;33m[*] Installing... [*]\033[0m"
    sleep(2)
    install = os.system("apt-get update && apt-get install -y build-essential slowhttptest python-pip git")
    install1 = os.system("pip2.7 install python-nmap paramiko scapy terminaltables")
    install2 = os.system("cp -R dedsploit/ /opt/ && cp dedsploit.py /opt/dedsploit && cp run.sh /opt/dedsploit && cp run.sh /usr/bin/dedsploit && chmod +x /usr/bin/dedsploit")

    print "\033[1;32m[!] Finished Installing! Run 'dedsploit' to run program [!]\033[0m"
    sys.exit()
else:
    print "Whoops! Something went wrong!"
