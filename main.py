#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
import my_logging as mylog
import my_analysis
import utils
#import packet_handling
import pcap

# Parametri
numero_queue = 33
logfile = "logfile.log"
pcapfile= "dropped_packets.pcap"
regex_list = ['CC{\w+}','CCRU{\w+}','doveva annà così fratellì','https://www.youtube.com/watch?v=dQw4w9WgXcQ']  # Lista di regex e stringhe bannate
service_type = 'Netcat' # Tipo di servizio, per ora e' rappresentato dal nome

# Funzione che analizza un pacchetto ricevuto
# dalla coda. Dopo aver verificato che il
# pacchetto e' IPv4, calcola la lunghezza
# dell'header IP, estrae porta sorgente e
# porta di destinazione, stampa a video i
# byte ricevuti e infine, dopo aver
# sottoposto i byte ricevuti ad una
# ricerca in base all'espressione regolare
# fornita, decide se lasciar passare il
# pacchetto o rifiutarlo.
def gestisci_pacchetto(pkt):
    payload = pkt.get_payload()
    payload_hex = payload.hex()

    if debug:
        log.nt_uplog('-------------')
        try:
            log.uplog('Data received: '+ payload[52:-1].decode('utf-8'))
        except UnicodeDecodeError:
            log.uplog("Can't decode received data")

    # Verifica della versione di IP del pacchetto:
    # Se non e' 4, non effettuo controlli
    # e lo accetto.
    versioneIP = payload_hex[0]
    if versioneIP != '4':
        log.uplog("Received a non-IPv4 packet, accepting it")
        pkt.accept()
        return

    inizioTCP = utils.calcola_lunghezza_ipv4(payload_hex[1])
    # TODO: verificare se SYN e' settato, in tal caso -> accept()

    if debug:
        ipSource = payload_hex[24:32]
        ipDest = payload_hex[32:40]
        log.uplog("Source IPv4: " + utils.calcolaIPv4(ipSource)+ "  Destination IPv4: " + utils.calcolaIPv4(ipDest))
        portaSource = payload[inizioTCP:inizioTCP+2].hex()
        portaSourceint = int(portaSource, 16)
        portaDest = payload[inizioTCP+2:inizioTCP+4].hex()
        portaDestint = int(portaDest, 16)
        log.uplog("Source port: " + str(portaSourceint) + "  Destination Port: " + str(portaDestint))
        log.uplog(pkt)
        #print(payload_hex)
        log.uplog(payload)
        log.nt_uplog('-------------')


    # Ricerca dell'espressione regolare
    match = shield.is_droppable(payload)
    if match:
        pkt.drop()
        pcap_exporter.make_packet_record(payload_hex)
        log.uplog("Packet dropped and added to pcap")
    else:
        pkt.accept()

# Verifica che l'utente sia root
if not utils.is_root():
    print("You need root privileges to run this application!")
    exit()

# Verifica se il programma e' stato
# avviato con il flag di debug
debug = utils.is_debug()

# Creazione oggetti di classe Log, Shield e PCAP
log = mylog.Log(logfile)
shield = my_analysis.Shield(regex_list, service_type, log)
pcap_exporter = pcap.PCAP(log, pcapfile)


log.uplog("Starting ips-cc")

if debug:
    log.uplog("Debug mode detected, printing iptables -L")
    log.uplog(utils.list_iptables())

# Creazione e bind dell'oggetto di classe NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, gestisci_pacchetto)

try:
    nfqueue.run()
except KeyboardInterrupt:
    log.uplog("Received Interrupt, shutting down")

nfqueue.unbind()
log.uplog("Stopped ips-cc")
log.endlog()
