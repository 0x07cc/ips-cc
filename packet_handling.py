"""Packet Handling module"""
import utils


class PacketHandling:

    def __init__(self, log, shield, debug=False, rst_ack=0):
        """ Metodo costruttore dell'oggetto.

            Args:
                log (obj): A [Log](my_logging.html#ips-cc.my_logging.Log) object.
                shield (obj): A [Shield](my_analysis.html#ips-cc.my_analysis.Shield) object.
                debug (bool): if `True`, every packet will be printed on screen and logged in the PCAP file.
                rst_ack (int): The dropping policy:
                * 0: only drop the packet;
                * 1: drop the packet and send a RST packet to kill the connection;
                * 2: drop the packet and send a ACK packet to continue the connection.
        """
        self.log = log
        self.shield = shield
        self.debug = debug
        self.rst_ack = rst_ack  # 0: drop; 1: RST in reply; 2: ACK in reply

        self.stats = None
        """ Variable that can be set by `PacketHandling.stats_hook`.
            Defaults to *None*."""

        self.pcap = None
        """ Variable that can be set by `PacketHandling.pcap_hook`.
            Defaults to *None*."""

        self.log.uplog("Starting Packet Handling Module")
        if self.debug:
            self.log.uplog("Debug mode, logging each packet")

    def stats_hook(self, statistics):
        """ Metodo setter di `PacketHandling.stats`:

            Viene chiamato dall'oggetto di classe Stats.
            Necessario per l'aggiornamento delle statistiche.

            Args:
                statistics (obj): A [Stats](stats.html#ips-cc.stats.Stats) object.
        """
        if statistics is not None:
            self.stats = statistics
            self.log.uplog("Statistics Module hooked to Handling Module")

    def pcap_hook(self, pcap_obj):
        """ Metodo setter di `PacketHandling.pcap`:

            Viene chiamato dall'oggetto di classe PCAP.
            Necessario per l'export dei pacchetti droppati.

            Args:
                pcap_obj (obj): A [PCAP](pcap.html#ips-cc.pcap.PCAP) object.
        """
        if pcap_obj is not None:
            self.pcap = pcap_obj
            self.log.uplog("PCAP Module hooked to Handling Module")

    def handle_packet(self, pkt):
        """ Metodo che verra' chiamato dal main e
            deve essere specificato in:
            nfqueue.bind(numero_queue, PacketHandling::handle_packet).
            Prende in input un oggetto di classe Packet e
            verifica se e' presente la flag di debug.
            Se e' presente stampa i dati del pacchetto
            a video e scrive il pacchetto nel file pcap.
            Infine, facendo uso dell'oggetto di classe
            Shield, decreta il verdetto del pacchetto.

            Args:
                pkt (obj): A [Packet](https://github.com/kti/python-netfilterqueue#packet-objects) object.
        """
        payload = pkt.get_payload()
        payload_hex = payload.hex()

        # Verifica della versione di IP del pacchetto:
        # Se non e' 4, non effettuo controlli e lo rifiuto.
        versioneIP = payload_hex[0]
        if versioneIP != '4':
            self.log.uplog("Received a non-IPv4 packet, dropping it")
            pkt.drop()
            if self.stats:
                self.stats.add_dropped()
            return

        # Calcolo Header Length: Uso campo IHL dell'header IPv4
        inizioTCP = utils.calcola_lunghezza_header(payload_hex[1])

        # TODO: Da qui implementare comportamento se il pacchetto non e' TCP.
        # Usare Protocol (ip.proto) di IPv4. 0x06 = TCP
        # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        # Se il pacchetto ricevuto non e' TCP, lo accetto TODO FIXME
        if payload_hex[19] != '6':
            self.log.uplog("Received a non-TCP packet, accepting it")
            pkt.accept()
            if self.stats:
                self.stats.add_accepted()
            return

        # Uso campo Data Offset dell'header TCP
        lunghezza_header_TCP = utils.calcola_lunghezza_header(payload_hex[inizioTCP * 2 + 24])
        # Dimensione totale degli header IPv4 + TCP, da qui iniziano i dati.
        dim_header = inizioTCP + lunghezza_header_TCP

        # Se il debug e' abilitato, scrive il pacchetto
        # nel file pcap, stampa a video gli indirizzi
        # e porte sorgente/destinazione. Infine
        # decodifica (UTF-8) e stampa a video
        # il campo Data del segmento TCP.
        if self.debug:
            # Salva OGNI pacchetto nel file .pcap, se l'exporter e' attivo
            if self.pcap:
                self.pcap.make_packet_record(payload_hex)

            self.log.nt_uplog('-------------')

            # "TCP Packet, x bytes"
            self.log.uplog(pkt)

            # Source/Dest IPv4 and ports
            try:
                ipSource = payload_hex[24:32]
                ipDest = payload_hex[32:40]
                ipSourceint = utils.IPv4HexToDotted(ipSource)
                ipDestint = utils.IPv4HexToDotted(ipDest)
                self.log.uplog("Source IPv4: " + ipSourceint
                               + "  Destination IPv4: " + ipDestint)

                portaSource = payload[inizioTCP:inizioTCP + 2].hex()
                portaSourceint = int(portaSource, 16)
                portaDest = payload[inizioTCP + 2:inizioTCP + 4].hex()
                portaDestint = int(portaDest, 16)
                self.log.uplog("Source port: " + str(portaSourceint)
                               + "  Destination Port: " + str(portaDestint))
            except ValueError:
                self.log.uplog("Debug: Error while decoding IPv4 or port")

            # TCP Data
            try:
                data_received = payload[dim_header:-1].decode('utf-8')
                self.log.uplog('Data received: ' + data_received)
            except UnicodeDecodeError:
                self.log.uplog("Can't decode received data")

            self.log.nt_uplog('-------------')

        # Verifica se il pacchetto e' da scartare
        match = self.shield.is_droppable(payload, dim_header)
        if match:
            pkt.drop()
            if self.stats:
                self.stats.add_dropped()

            # Salvataggio del pacchetto solo se l'IPS non e' in debug mode
            # e l'exporter e' attivo, altrimenti e' stato gia' salvato sopra.
            if not self.debug:
                if self.pcap:
                    self.pcap.make_packet_record(payload_hex)

            self.log.uplog("Packet dropped")

            # Verifico se devo solo droppare il pacchetto (rst_ack == 0);
            # dropparlo e inviare un pacchetto RST (rst_ack == 1) oppure
            # dropparlo e inviare un pacchetto ACK (rst_ack == 2).
            if self.rst_ack != 0:
                # Dal campo Total Length di IPv4
                total_packet_length = int(payload_hex[4:8], 16)

                [ipSource, ipDest, portaSource, portaDest, newAck, newSeq] = utils.genera_argomenti(
                    payload_hex, inizioTCP, self.shield, self.rst_ack,
                    total_packet_length - dim_header)

                utils.genera_RST(ipSource, ipDest, portaSource, portaDest, newAck, newSeq, self.rst_ack)
        else:
            pkt.accept()
            if self.stats:
                self.stats.add_accepted()
