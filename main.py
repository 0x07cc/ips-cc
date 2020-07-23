#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
import re #TODO: si puo' importare meno?
import time
import my_logging as mylog
import utils

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
		print("Pacchetto non IPv4")
		pkt.accept()
		return

	inizioTCP = calcola_lunghezza_ipv4(payload_hex[1])

	portaSource = payload[inizioTCP:inizioTCP+2].hex()
	portaSourceint = int(portaSource, 16)
	log.uplog("porta source: " + str(portaSourceint))
	
	portaDest = payload[inizioTCP+2:inizioTCP+4].hex()
	portaDestint = int(portaDest, 16)
	log.uplog("porta destinazione: " + str(portaDestint))
	
	# TODO: verificare se SYN e' settato, in tal caso -> accept()
	log.uplog(pkt)
	#print(payload_hex)
	log.uplog(payload)
	log.nt_uplog('-------------')
	
	# Ricerca dell'espressione regolare
	match = regexp_compilata.search(payload)
	if match:
		pkt.drop()
		log.uplog("Pacchetto droppato")
	else:
		pkt.accept()

log = mylog.Log(logfile)
log.uplog("ips-cc avviato")

# Verifica che l'utente sia root
if not utils.is_root():
    log.uplog("L'applicazione ha bisogno dei permessi di root!")
    log.endlog()
    exit()

# Creazione e bind dell'oggetto di classe NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, gestisci_pacchetto)

try:
	nfqueue.run()
except KeyboardInterrupt:
	print('')

nfqueue.unbind()
log.uplog("ips-cc terminato")
log.endlog()
