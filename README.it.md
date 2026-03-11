[English](README.md) | [Italian](README.it.md)
# Un mini-IPS per CC
Un programma che ha lo scopo di bloccare il transito di pacchetti TCP/UDP contenenti un dato pattern.  
Fa uso di nf_queue, disponibile nel Kernel Linux.  
Può essere programmato per bloccare traffico in entrata o in uscita semplicemente modificando la regola iptables.  
Non gestisce i pacchetti IPv6.  
Può inoltre essere programmato per inviare risposte RST/ACK ai pacchetti TCP bloccati per killare/continuare la connessione.

## Arch Linux: Quick Start
Installazione:
1. Assicurarsi di avere Python > 3.7
1. Installare gli strumenti per compilare: `sudo pacman -S base-devel python-setuptools cython`
1. Installare git: `sudo pacman -S git`
1. Assicurarsi di avere iptables
1. Installare libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Installare NetfilterQueue:   `git clone https://github.com/oremanj/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire la regola per iptables: `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py -d`  (-d indica debug)

## Alpine Linux: Quick Start (nftables)
Installazione (come utente root):
1. Installare gli strumenti per compilare: `apk add cython py3-setuptools gcc python3-dev musl-dev linux-headers`
1. Installare git: `apk add git`
1. Installare ed avviare nftables: `apk add nftables; rc-service nftables start`
1. Installare libnetfilter_queue: `apk add libnetfilter_queue libnetfilter_queue-dev libnfnetlink-dev`
1. Installare NetfilterQueue:  `git clone https://github.com/oremanj/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Inserire una regola nftables come ad esempio `tcp dport 2222 queue to 33` in una chain di input, dove 2222 è la porta su cui è in ascolto un applicativo server da proteggere
1. Avviare lo script come utente root: `sudo ./main.py -d`  (-d indica debug)

## Regole di esempio iptables
1. Default: Blocca traffico in entrata dai clients verso una applicazione in esecuzione sulla macchina (server): `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`
1. Blocca traffico in uscita da una applicazione in esecuzione sulla macchina (server) verso i clients: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`

## Debug mode
In modalità di debug il programmerà stamperà a schermo ogni pacchetto che gestisce e lo salverà in un file .pcap.  
Per attivarla: `sudo ./main.py -d` or `sudo ./main.py --debug`
