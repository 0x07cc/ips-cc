# Tools module
import os
import subprocess
import sys

# Funzione che calcola la lunghezza dell'header IPv4
# basandosi sul valore IHL (Internet Header Length).
#
# Documentazione di riferimento:
# https://en.wikipedia.org/wiki/IPv4#IHL
def calcola_lunghezza_header(carattere):
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

# Funzione che ritorna la stringa contenente l'output del comando 'iptables -L -n'
def list_iptables():
    process = subprocess.run(["iptables", "-L", "-n"], stdout=subprocess.PIPE, timeout=5)
    return process.stdout.decode()

# Funzione che ritorna True se il programma e'
# stato avviato passando l'argomento -d o --debug
def is_debug():
    if len(sys.argv) > 1:
        if "-d" in sys.argv or "--debug" in sys.argv:
            return True
    return False

# TODO Docs
def genera_RST(IPSorgente, IPDestinatario, PortaSorgente,
               PortaDestinazione, oldACK):
    # Dotted IP To Hex
    source  = IPSorgente.split(".")
    source0 = hex(int(source[0]))
    source1 = hex(int(source[1]))
    source2 = hex(int(source[2]))
    source3 = hex(int(source[3]))

    dest  = IPDestinatario.split(".")
    dest0 = hex(int(source[0]))
    dest1 = hex(int(source[1]))
    dest2 = hex(int(source[2]))
    dest3 = hex(int(source[3]))

    # IP Header with no checksum set
    header = {}
    header[0]  = 0x45 # IPv4, Length=20
    header[1]  = 0x00
    header[2]  = 0x00
    header[3]  = 0x28 # Total Length
    header[4]  = 0x61 # Identification 1
    header[5]  = 0xb5 # Identification 2
    header[6]  = 0x00
    header[7]  = 0x00
    header[8]  = 0x40 # TTL
    header[9]  = 0x06 # Protocol = TCP
    header[10] = 0x00 # Checksum 1
    header[11] = 0x00 # Checksum 2
    header[12] = int(source0[2:], 16) # 127
    header[13] = int(source1[2:], 16) # 0
    header[14] = int(source2[2:], 16) # 0
    header[15] = int(source3[2:], 16) # 1
    header[16] = int(dest0[2:], 16) # 192
    header[17] = int(dest1[2:], 16) # 168
    header[18] = int(dest2[2:], 16) # 1
    header[19] = int(dest3[2:], 16) # 15

    # Calculating checksum
    checksum = checksum_IPv4_header(header) # e.g. 0xB861
    checksum1 = checksum[2:4] # e.g. B8
    checksum2 = checksum[4:6] # e.g. 61
    # Setting checksum in header
    header[10] = int(checksum1, 16)
    header[11] = int(checksum2, 16)

    # Ports
    portaS = hex(PortaSorgente)
    portaD = hex(PortaDestinazione)
    portaS = "0x"+(6-len(portaS))*"0"+portaS[2:]
    portaD = "0x"+(6-len(portaD))*"0"+portaD[2:]

    # TCP Header with no checksum set
    TCPheader = {}
    TCPheader[0]  = int(portaS[2:4], 16) # Source Port 1
    TCPheader[1]  = int(portaS[4:6], 16) # Source Port 2
    TCPheader[2]  = int(portaD[2:4], 16) # Dest Port 1
    TCPheader[3]  = int(portaD[4:6], 16) # Dest Port 2
    TCPheader[4]  = oldACK[0] # Sequence Number 1
    TCPheader[5]  = oldACK[1] # Sequence Number 2
    TCPheader[6]  = oldACK[2] # Sequence Number 3
    TCPheader[7]  = oldACK[3] # Sequence Number 4
    TCPheader[8]  = 0x00 # Acknowledgment 1
    TCPheader[9]  = 0x00 # Acknowledgment 2
    TCPheader[10] = 0x00 # Acknowledgment 3
    TCPheader[11] = 0x00 # Acknowledgment 4
    TCPheader[12] = 0x50 # Header Length
    TCPheader[13] = 0x04 # Flags RST 04, ACK 10
    TCPheader[14] = 0x00 # Window size 1
    TCPheader[15] = 0x00 # Window size 2
    TCPheader[16] = 0x00 # Checksum 1
    TCPheader[17] = 0x00 # Checksum 2
    TCPheader[18] = 0x00 # Urgent pointer 1
    TCPheader[19] = 0x00 # Urgent pointer 2

    PseudoHeader = {}
    PseudoHeader[0] = int(source0[2:], 16) # Source 1
    PseudoHeader[1] = int(source1[2:], 16) # Source 2
    PseudoHeader[2] = int(source2[2:], 16) # Source 3
    PseudoHeader[3] = int(source3[2:], 16) # Source 4
    PseudoHeader[4] = int(dest0[2:], 16)   # Source 1
    PseudoHeader[5] = int(dest1[2:], 16)   # Source 2
    PseudoHeader[6] = int(dest2[2:], 16)   # Source 3
    PseudoHeader[7] = int(dest3[2:], 16)   # Source 4
    PseudoHeader[8] = 0x00
    PseudoHeader[9] = 0x06 # Protocol
    PseudoHeader[10] = 0x00 # TCP length 1
    PseudoHeader[11] = 0x28 # TCP length 2 # TODO ?

    # Merging dictionaries
    merged_dict = PseudoHeader.copy()
    for i in range(20):
        merged_dict[i+12]=TCPheader[i]

    # Calculating checksum
    checksum = checksum_IPv4_header(merged_dict) # e.g. 0xB861
    checksum1 = checksum[2:4] # e.g. B8
    checksum2 = checksum[4:6] # e.g. 61
    # Setting checksum in header
    TCPheader[16] = int(checksum1, 16)
    TCPheader[17] = int(checksum2, 16)

    # DEBUG TODO REMOVE
    print("Pseudo")
    for i in PseudoHeader:
        print(str(i) + " " + hex(PseudoHeader[i]))
    print(" ")
    print("Merged")
    for i in merged_dict:
        print(str(i) + " " + hex(merged_dict[i]))
    print(" ")
    print("TCP Header final")
    for i in TCPheader:
        print(str(i) + " " + hex(TCPheader[i]))

    # Dictionary to byte
    packet = b''
    for i in header:
        packet = packet + bytes([header[i]])

# Calculates the checksum for an IP header
# Author: Grant Curell
def checksum_IPv4_header(ip_header):
    cksum = 0
    pointer = 0
    size = len(ip_header)
    while size > 1:
        cksum += int((str("%02x" % (ip_header[pointer],)) + 
                      str("%02x" % (ip_header[pointer+1],))), 16)
        size -= 2
        pointer += 2
    if size:
        cksum += ip_header[pointer]
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >>16)
    cksum = hex((~cksum) & 0xFFFF)
    lenght = len(cksum)
    # Filling with zero (e.g. 0xb1a => 0x0b1a)
    return "0x"+(6-lenght)*"0"+cksum[2:]
