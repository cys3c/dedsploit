import os, sys, platform

sys.path.append('src/')
from mainLib import *

if not os.geteuid() == 0:
    sys.exit(R + "[!] You are not a root user! [!]" + W )

header = C + """

    .___         .___             .__         .__  __
  __| _/____   __| _/____________ |  |   ____ |__|/  |_
 / __ |/ __ \ / __ |/  ___/\____ \|  |  /  _ \|  \   __|
/ /_/ \  ___// /_/ |\___ \ |  |_> >  |_(  <_> )  ||  |
\____ |\___  >____ /____  >|   __/|____/\____/|__||__|
     \/    \/     \/    \/ |__|                         """

print header
print O + "Made for defhacks() 2016" + W
print "Penetration Testing Framework for Network Protocol Attacks"
print "You are currently using " + LG + str(platform.system()) + " " + str(platform.release()) + W

if platform.system() != "Linux":
    print R + "[!] You are not using Linux! Please consider switching [!]" + W

table_data = [
    ["Network Information", ""],
    ["Local IP Address: ", str(lan_ip)],
    ["Public IP Address: ", str(public_ip)],
    ["MAC Address: ", str(mac_address)],
    ["Gateway IP: ", str(gateway_ip)]
]

table = AsciiTable(table_data)
print table.table

def main():
    while True:
        try:
            print LC + "Type in a command. If you require assistance, type 'help'. To exit the program, use Ctrl + C or type 'exit'"
            options = raw_input(P + ">> " + W )
            if options == "help":
                help_options()
                continue
            elif options == "ssh":
                ssh()
            elif options == "smtp":
                smtp()
            elif options == "http":
                http()
            elif options == "misc":
                misc()
            elif options == "recon":
                recon()
            elif options == "clear":
                call(["clear"])
                continue
            elif options == "exit":
                # sys.exit(G + "[*] Goodbye! Remember to Hack the Gibson! [*]" + W)
                raise KeyboardInterrupt
            else:
                continue
        except KeyboardInterrupt:
            sys.exit(G + "\n[*] Goodbye! Remember to Hack the Gibson! [*]" + W)

if __name__ == "__main__":
    main()
