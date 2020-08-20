#!/usr/bin/env python3
'''
 ips-cc main script.
 Launch it witch "sudo ./main.py".
'''
from netfilterqueue import NetfilterQueue
import my_logging as mylog
import my_analysis
import utils
import packet_handling
import pcap

# Parametri
numero_queue = 33
logfile = "logfile.log"
pcapfile= "dropped_packets.pcap"
regex_list = ['CC{\w+}','CCRU{\w+}','doveva annà così fratellì','https://www.youtube.com/watch?v=dQw4w9WgXcQ']  # Lista di regex e stringhe bannate
service_type = 'Netcat' # Tipo di servizio, per ora e' rappresentato dal nome


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
handling = packet_handling.PacketHandling(log, shield, pcap_exporter, debug)

log.uplog("Starting ips-cc")

if debug:
    log.uplog("Debug mode detected, printing iptables -L")
    log.uplog(utils.list_iptables())

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
