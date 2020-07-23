#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
import re #TODO: si puo' importare meno?
import my_logging as mylog
import utils
#import packet_handling

# Parametri
numero_queue = 33
regexp_compilata = re.compile(b'CC{\w+}') 
logfile = "logfile.log"

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
	log.nt_uplog('-------------')
	payload = pkt.get_payload()
	payload_hex = payload.hex()

	log.uplog('Server netcat sent: '+ payload[52:-1].decode('ascii')) #stampa quello che scrivi su netcat, utile per debugging
	
	# Verifica della versione di IP del pacchetto:
	# Se non e' 4, non effettuo controlli
	# e lo accetto.
	versioneIP = payload_hex[0]
	if versioneIP != '4':
		print("Received a non-IPv4 packet, accepting it")
		pkt.accept()
		return

	inizioTCP = utils.calcola_lunghezza_ipv4(payload_hex[1])

	portaSource = payload[inizioTCP:inizioTCP+2].hex()
	portaSourceint = int(portaSource, 16)
	log.uplog("Source Port: " + str(portaSourceint))
	
	portaDest = payload[inizioTCP+2:inizioTCP+4].hex()
	portaDestint = int(portaDest, 16)
	log.uplog("Destination Port: " + str(portaDestint))
	
	# TODO: verificare se SYN e' settato, in tal caso -> accept()
	log.uplog(pkt)
	#print(payload_hex)
	log.uplog(payload)
	log.nt_uplog('-------------')
	
	# Ricerca dell'espressione regolare
	match = regexp_compilata.search(payload)
	if match:
		pkt.drop()
		log.uplog("Packet dropped")
	else:
		pkt.accept()

log = mylog.Log(logfile)

# Verifica che l'utente sia root
if not utils.is_root():
	log.uplog("You need root privileges to run this application")
	log.endlog()
	exit()

log.uplog("Starting ips-cc")


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
