#Packet Handling Module
import utils

class PacketHandling:

    # Funzione costruttore dell'oggetto.
    # Prende in input un oggetto di classe Log,
    # un oggetto di classe Shield, un oggetto
    # di classe PCAP e un valore booleano
    # utilizzato per determinare se
    # stampare o meno le linee di debug.
    def __init__(self, log, shield, pcap, debug=False, rst_ack=0):
        self.log = log
        self.shield = shield
        self.pcap = pcap
        self.debug = debug
        self.rst_ack = rst_ack # 0: only drop; 1: RST in reply; 2: ACK in reply
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

        # Calcolo Header Length: Uso campo IHL dell'header IPv4
        inizioTCP = utils.calcola_lunghezza_header(payload_hex[1])
        # Uso campo Data Offset dell'header TCP
        lunghezza_header_TCP = utils.calcola_lunghezza_header(payload_hex[inizioTCP*2+24])
        # Dimensione totale degli header IPv4 + TCP, da qui iniziano i dati.
        dim_header = inizioTCP + lunghezza_header_TCP

        # TODO: verificare se SYN e' settato, in tal caso -> accept()
        # Verificare prima se si puo' trasmettere dati anche col flag
        # SYN, altrimenti si crea una vulnerabilita'.

        # Se il debug e' abilitato, scrive il pacchetto
        # nel file pcap, stampa a video gli indirizzi
        # e porte sorgente/destinazione. Infine
        # decodifica (UTF-8) e stampa a video
        # il campo Data del segmento TCP.
        if self.debug:
            # Salva OGNI pacchetto nel file .pcap
            self.pcap.make_packet_record(payload_hex)

            self.log.nt_uplog('-------------')

            # "TCP Packet, x bytes"
            self.log.uplog(pkt)

            # Source/Dest IPv4 and ports
            try:
                ipSource = payload_hex[24:32]
                ipDest = payload_hex[32:40]
                ipSourceint = utils.calcolaIPv4(ipSource)
                ipDestint = utils.calcolaIPv4(ipDest)
                self.log.uplog("Source IPv4: " +ipSourceint +
                               "  Destination IPv4: " + ipDestint)

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
                self.log.uplog('Data received: ' + payload[dim_header:-1].decode('utf-8'))
            except UnicodeDecodeError:
                self.log.uplog("Can't decode received data")

            self.log.nt_uplog('-------------')

        # Verifica se il pacchetto e' da scartare
        match = self.shield.is_droppable(payload, dim_header)
        if match:
            pkt.drop()

            if not self.debug:
                self.pcap.make_packet_record(payload_hex)
            # Devo salvarlo SOLO se non siamo in debug mode,
            # altrimenti e' stato gia' salvato sopra.
            self.log.uplog("Packet dropped and added to pcap")

            # Verifico se devo solo droppare il pacchetto (rst_ack == 0);
            # dropparlo e inviare un pacchetto RST (rst_ack == 1) oppure
            # dropparlo e inviare un pacchetto ACK (rst_ack == 2).
            if self.rst_ack != 0:
                # Dal campo Total Length di IPv4
                total_packet_length = int(payload_hex[4:8],16)

                [ipSourceint, ipDestint, portaSourceint, portaDestint, newAck, newSeq] = utils.genera_argomenti(
                    payload_hex, inizioTCP, ipSourceint, ipDestint, 
                    portaDestint , portaSourceint, self.shield, self.rst_ack, 
                    total_packet_length-dim_header)

                utils.genera_RST(ipSourceint, ipDestint, portaSourceint, portaDestint, newAck, newSeq, self.rst_ack)
        else:
            pkt.accept()
