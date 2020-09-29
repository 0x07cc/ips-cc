#!/usr/bin/env python3
'''
 ips-cc main script.
 Edit parameters, append the iptables rule, then launch it
 with "sudo ./main.py" or "sudo ./main.py -d" for debug mode.
 This script will block any packet with the Data field matching
 at least one of the regular expressions in regex_list.
 In debug mode every packet will be printed on screen and saved in pcap file.
'''
from netfilterqueue import NetfilterQueue
import logging 
import analysis
import utils
import packet_handling
import pcap

# Parameters
numero_queue = 33
logfile = "logfile.log"
pcapfile= "dropped_packets.pcap"

# This dictionary gives the list of banned strings/regex for a given iptables rule (I-3000 = blocking INPUT packets on port 3000)
regex_list = {'I-2222' : ['CC{\w+}','CCRU{\w+}','doveva annà così fratellì','https://www.youtube.com/watch?v=dQw4w9WgXcQ' ],
              'O-3000' : ["la mi passsword","sito/admin/freesoldi.php"],
              'I-3000' : ["python","Or 1=1","UNION"]
              }

# Service Type for any given port
services_type = {2222:'Raw', 3000:'HTTP'} 


# rst_ack controls the packet dropping policy:
# 0: only drop the packet;
# 1: drop the packet and send a RST packet to kill the connection;
# 2: drop the packet and send a ACK packet to continue the connection.
rst_ack = 2

# Verifica che l'utente sia root
if not utils.is_root():
    print("You need root privileges to run this application!")
    exit()

# Verifica se il programma e' stato avviato con il flag di debug
debug = utils.is_debug()

# This set the logger treshold level 
if debug:
    log_level = "DEBUG"
else:
    log_level = "INFO"


# Creazione oggetti di classe Log, Shield, PCAP e PacketHandling
log = logging.Log(logfile, log_level)
shield = analysis.Shield(regex_list, services_type, log)
pcap_exporter = pcap.PCAP(log, pcapfile)
handling = packet_handling.PacketHandling(log, shield, pcap_exporter, debug, rst_ack)

log.uplog("Starting ips-cc")
iptables_list = utils.list_iptables()
shield.set_services(iptables_list, numero_queue)


log.uplog("Debug mode detected, printing iptables -L -n","DEBUG")
log.uplog(iptables_list,"DEBUG")

# Creazione e bind dell'oggetto di classe NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, handling.handle_packet)

try:
    nfqueue.run()
except KeyboardInterrupt:
    log.uplog("Received Interrupt, shutting down")

nfqueue.unbind()
log.uplog("Stopped ips-cc")
log.endlog()
