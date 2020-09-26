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
import my_logging as mylog
import my_analysis
import utils
import packet_handling
import pcap

# Parameters
numero_queue = 33
logfile = "logfile.log"
pcapfile= "dropped_packets.pcap"
regex_list = ['CC{\w+}','CCRU{\w+}','doveva annà così fratellì','https://www.youtube.com/watch?v=dQw4w9WgXcQ']  # Lista di regex e stringhe bannate
service_type = 'Netcat' # Tipo di servizio, per ora e' rappresentato dal nome
# rst_ack controls the packet dropping policy:
# 0: only drop the packet;
# 1: drop the packet and send a RST packet to kill the connection;
# 2: drop the packet and send a ACK packet to continue the connection.
rst_ack = 1

# Verifica che l'utente sia root
if not utils.is_root():
    print("You need root privileges to run this application!")
    exit()

# Verifica se il programma e' stato avviato con il flag di debug
debug = utils.is_debug()

# Creazione oggetti di classe Log, Shield, PCAP e PacketHandling
log = mylog.Log(logfile)
shield = my_analysis.Shield(regex_list, service_type, log)
pcap_exporter = pcap.PCAP(log, pcapfile)
handling = packet_handling.PacketHandling(log, shield, pcap_exporter, debug, rst_ack)

log.uplog("Starting ips-cc")

if debug:
    log.uplog("Debug mode detected, printing iptables -L -n")
    iptables_list = utils.list_iptables()
    shield.set_rules(iptables_list, numero_queue)
    log.uplog(iptables_list)

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
