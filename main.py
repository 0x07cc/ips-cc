#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
import re #TODO: si puo' importare meno?
import my_logging as mylog
import utils
import packet_handling

# Parametri
numero_queue = 33
regexp_compilata = re.compile(b'CC{\w+}') 
logfile = "logfile.log"


log = mylog.Log(logfile)

# Verifica che l'utente sia root
if not utils.is_root():
    log.uplog("You need root privileges to run this application")
    log.endlog()
    exit()

log.uplog("Starting ips-cc")


# Creazione e bind dell'oggetto di classe NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(numero_queue, packet_handling.gestisci_pacchetto)

try:
	nfqueue.run()
except KeyboardInterrupt:
	log.uplog("Received Interrupt, shutting down")

nfqueue.unbind()
log.uplog("Stopped ips-cc")
log.endlog()
