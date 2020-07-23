# Tools module
import os
import subprocess
import sys

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

# Funzione che ritorna la stringa
# contenente l'output del comando
# 'iptables -L'
def list_iptables():
    process = subprocess.run(["iptables", "-L"], stdout=subprocess.PIPE, timeout=5)
    return process.stdout.decode()

# Funzione che ritorna True se il programma e'
# stato avviato passando l'argoment -d o --debug
def is_debug():
    if len(sys.argv) > 1:
        if "-d" in sys.argv or "--debug" in sys.argv:
            return True
    return False

