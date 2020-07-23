# Modulo di Utilita' per IP
import os

# Funzione che calcola la lunghezza del pacchetto IPv4
# basandosi sul valore IHL (Internet Header Length).
#
# Documentazione di riferimento:
# https://en.wikipedia.org/wiki/IPv4#IHL
def calcola_lunghezza_ipv4(carattere):
    lunghezza = 20
    ihl = int(carattere, 16)
    lunghezza = (ihl*32)//8
    return lunghezza

# Funzione che controlla se l'utente
# che ha avviato lo script e' root.
def is_root():
    if os.geteuid() != 0:
        return False
    return True
