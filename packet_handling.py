#Packet Handling Module
import utils

class PacketHandling:

    # Funzione costruttore dell'oggetto.
    # Prende in input un oggetto di classe Log,
    # un oggetto di classe Shield, un oggetto
    # di classe PCAP e un valore booleano
    # utilizzato per determinare se
    # stampare o meno le linee di debug.
    def __init__(self, log, shield, pcap, debug=False):
        self.log = log
        self.shield = shield
        self.pcap = pcap
        self.debug = debug
        self.log.uplog("Starting Packet Handling Module")
        if self.debug:
            self.log.uplog("Debug mode, logging each packet")

    # Funzione che verra' chiamata dal main e
    # deve essere specificata in:
    # nfqueue.bind(numero_queue, PacketHandling::handle_packet).
    # Prende in input un oggetto di classe Packet e
    # verifica se e' presente la flag di debug.
    # Se e' presente stampa i dati del pacchetto
    # a video e scrive il pacchetto nel file pcap.
    # Infine , facendo uso dell'oggetto di classe
    # Shield, decreta il verdetto del pacchetto.
    def handle_packet(self, pkt):
        payload = pkt.get_payload()
        payload_hex = payload.hex()

        # Verifica della versione di IP del pacchetto:
        # Se non e' 4, non effettuo controlli e lo rifiuto.
        versioneIP = payload_hex[0]
        if versioneIP != '4':
            self.log.uplog("Received a non-IPv4 packet, dropping it")
            pkt.drop()
            return

        # TODO: verificare se SYN e' settato, in tal caso -> accept()
        # Verificare prima se si puo' trasmettere dati anche col flag
        # SYN, altrimenti si crea una vulnerabilita'.

        # Se il debug e' abilitato, scrive il pacchetto
        # nel file pcap, stampa a video gli indirizzi
        # e porte sorgente/destinazione. Infine
        # decodifica (UTF-8) e stampa a video
        # il campo Data del segmento TCP.
        if self.debug:
            self.pcap.make_packet_record(payload_hex)
            inizioTCP = utils.calcola_lunghezza_ipv4(payload_hex[1])
            self.log.nt_uplog('-------------')

            # "TCP Packet, x bytes"
            self.log.uplog(pkt)

            # Source/Dest IPv4 and port
            try:
                ipSource = payload_hex[24:32]
                ipDest = payload_hex[32:40]
                self.log.uplog("Source IPv4: " + utils.calcolaIPv4(ipSource) +
                               "  Destination IPv4: " + utils.calcolaIPv4(ipDest))
                portaSource = payload[inizioTCP:inizioTCP+2].hex()
                portaSourceint = int(portaSource, 16)
                portaDest = payload[inizioTCP+2:inizioTCP+4].hex()
                portaDestint = int(portaDest, 16)
                self.log.uplog("Source port: " + str(portaSourceint) +
                               "  Destination Port: " + str(portaDestint))
            except:
                self.log.uplog("Debug: Error while decoding IPv4 or port")

            # TCP Data
            try:
                self.log.uplog('Data received: ' + payload[52:-1].decode('utf-8'))
                # TODO: Va usato il data offset dell'header TCP.
                # Non e' sempre lungo 52 Bytes!
                # Vedere Drive per l'implementazione
            except UnicodeDecodeError:
                self.log.uplog("Can't decode received data")

            self.log.nt_uplog('-------------')


        # Verifica se il pacchetto e' da scartare
        match = self.shield.is_droppable(payload)
        if match:
            pkt.drop()
            if not self.debug:
                self.pcap.make_packet_record(payload_hex)
            self.log.uplog("Packet dropped and added to pcap")
        else:
            pkt.accept()
