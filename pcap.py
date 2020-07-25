# PCAP export module
import time
import binascii
import os

class PCAP:

    # Funzione costruttore dell'oggetto.
    # Al momento distrugge il vecchio file PCAP,
    # crea un header PCAP e lo appende al file.
    # Prende in input un oggetto di classe Log e una
    # stringa contenente il nome del file di output.
    def __init__(self, log, filename="dropped_packets.pcap"):
        self.log = log
        log.uplog("Starting PCAP exporting module")

        try:
            self.outputFile = open(filename,"wb")
        except:
            log.uplog("Error while opening " + filename)
            exit()

        self.header = self.make_header()
        self.outputFile.write(self.header)
        # Flush is used to confirm the writing to the file.
        self.outputFile.flush()
        os.fsync(self.outputFile.fileno())

    # Funzione distruttore dell'oggetto:
    # chiude il file di output.
    def __del__(self):
        self.outputFile.close()

    # Funzione che ritorna bytes dell'header PCAP.
    # length e' un parametro al momento non
    # usato che dovrebbe influenzare SnapLen.
    # Documentazione di riferimento:
    # http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-gharris-opsawg-pcap.xml&modeAsFormat=html/ascii&type=ascii#packet_record
    def make_header(self, length=4):
        header  = 'D4C3B2A1' # Magic Number in little endian
        header += '02000400' # Version 2.4
        header += '00000000' # Reserved 1
        header += '00000000' # Reserved 2

        # SnapLen: maximum number of octets
        # captured from each packet
        header += '00000400' #TODO: capire se va aumentato

        # LinkType: Raw IPv4
        # Documentazione di riferimento:
        # http://www.tcpdump.org/linktypes.html
        header += 'e4000000' # e4 (Hex) = 228 (Dec)

        header_byte = binascii.unhexlify(header)
        return header_byte

    # Funzione che aggiunge un record al file PCAP.
    # Richiede in ingresso una stringa contenente
    # un pacchetto IP (In genere inizia con '450000')
    def make_packet_record(IP_packet):
        # Seconds and microseconds
        time_hex = hex(int(time.time()))[2:10] # Seconds from epoch
        time_1= time_hex[0:2]
        time_2= time_hex[2:4]
        time_3= time_hex[4:6]
        time_4= time_hex[6:8]
        time_dec = '00000000' # We don't care about ms
        packet_record = time_4 + time_3 + time_2 + time_1 + time_dec

        # Packet Length
        # IP_packet is a string, a byte is represented by two characters.
        packet_length_int = len(IP_packet)//2
        packet_length_hex = hex(packet_length_int)[2:]
        # Fill the rest with zero
        packet_length = packet_length_hex + '0'*(8-len(packet_length_hex))
        packet_record += packet_length # Captured Packet Length
        packet_record += packet_length # Original Packet Length

        # IP Packet
        packet_record += IP_packet

        packet_record_bytes = binascii.unhexlify(packet_record)
        self.outputFile.write(packet_record_bytes)
        # Flush is used to confirm the writing to the file.
        self.outputFile.flush()
        os.fsync(self.outputFile.fileno())

#make_pcap('4500003c7b8d4000400633c7c0a80063041fc63dd6b00050eecf76d900000000a002faf0a4300000020405b40402080a9a7a46520000000001030307')
