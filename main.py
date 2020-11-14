#!/usr/bin/env python3
"""
ips-cc main script.

Edit parameters, append the iptables rule, then launch it
with:

    sudo ./main.py

This script will block any TCP packet with the Data field matching
at least one of the regular expressions in `regex_list`.

In debug mode (`sudo ./main.py -d`) every packet will be printed on the screen
and saved in the pcap file.

This script doesn't handle IPv6 packets.
"""
import my_logging as mylog
import my_analysis
import utils
import packet_handling
import pcap
import stats

# Parameters
queue_number: int = 33
"""The NetfilterQueue queue number. Defaults to *33*."""

log_file: str = "logfile.log"
"""Filename where the log will be stored.
Defaults to *"logfile.log"*."""

pcap_file: str = "dropped_packets.pcap"
"""Filename where the dropped packets will be stored.
Defaults to *"dropped_packets.pcap"*."""

regex_list: list = ['CC{\w+}', 'CCRU{\w+}', 'doveva annà così fratellì', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ']
"""List of banned Regular Expressions and strings."""

service_type: str = 'Netcat'
"""str: Name of the service. Useless at the moment."""

dropping_policy: int = 1
"""int: Parameter that controls the packet dropping policy.
Possible_Values:
    * 0: only drop the packet;
    * 1: drop the packet and send a RST packet to kill the connection;
    * 2: drop the packet and send a ACK packet to continue the connection. """

# If the module is started directly by the interpreter
if __name__ == '__main__':
    from netfilterqueue import NetfilterQueue

    # Checking root privileges
    if not utils.is_root():
        print("You need root privileges to run this application!")
        exit(-1)

    # Checking debug flag status (-d or --debug)
    debug = utils.is_debug()

    # Indispensable objects instantiation
    log = mylog.Log(log_file)
    shield = my_analysis.Shield(regex_list, service_type, log)
    handling = packet_handling.PacketHandling(log, shield, debug, dropping_policy)

    # Optional objects instantiation: comment them to disable
    statistics = stats.Stats(log, handling)
    pcap_exporter = pcap.PCAP(log, handling, pcap_file)

    log.uplog("Starting ips-cc")

    # Retrieving iptables list and determining the policy of each rule
    iptables_list = utils.list_iptables()
    shield.set_rules(iptables_list, queue_number)

    if debug:
        log.uplog("Debug mode detected, printing iptables -L -n")
        log.uplog(iptables_list)

    # NetfilterQueue object instantiation and binding
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number, handling.handle_packet)

    # "run()" is a blocking method. The program will close on CTRL-C
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        log.uplog("Received Interrupt, shutting down")

    nfqueue.unbind()
    log.uplog("Stopped ips-cc")
    log.endlog()
