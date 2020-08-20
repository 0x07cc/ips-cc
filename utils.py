# Tools module
import os
import subprocess
import sys

# Funzione che calcola la lunghezza dell'header IPv4
# basandosi sul valore IHL (Internet Header Length).
#
# Documentazione di riferimento:
# https://en.wikipedia.org/wiki/IPv4#IHL
def calcola_lunghezza_ipv4(carattere):
    lunghezza = 20
    ihl = int(carattere, 16)
    lunghezza = (ihl*32)//8
    return lunghezza

# Funzione che ritorna la stringa dell'indirizzo IPv4 (dotted)
# basandosi sulla stringa esadecimale passatagli.
def calcolaIPv4(stringa_hex):
    primo = int(stringa_hex[0:2], 16)
    secondo = int(stringa_hex[2:4], 16)
    terzo = int(stringa_hex[4:6], 16)
    quarto = int(stringa_hex[6:8], 16)
    return '%d.%d.%d.%d' % (primo, secondo, terzo, quarto)

# Funzione che controlla se l'utente che ha avviato lo script e' root.
def is_root():
    if os.geteuid() != 0:
        return False
    return True

# Funzione che ritorna la stringa contenente l'output del comando 'iptables -L'
def list_iptables():
    process = subprocess.run(["iptables", "-L"], stdout=subprocess.PIPE, timeout=5)
    return process.stdout.decode()

# Funzione che ritorna True se il programma e'
# stato avviato passando l'argomento -d o --debug
def is_debug():
    if len(sys.argv) > 1:
        if "-d" in sys.argv or "--debug" in sys.argv:
            return True
    return False
