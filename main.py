#!/usr/bin/env python3
'''
 ips-cc main script.
 Edit config file, append the firewall rule, then launch it
 with "sudo ./main.py" or "sudo ./main.py -d" for debug mode.
 This script will block any packet with the Data field matching
 at least one of the regular expressions in rules.
 In debug mode every packet will be printed on screen and saved in pcap file.
'''
from netfilterqueue import NetfilterQueue
import my_logging as mylog
import my_analysis
import utils
import packet_handling
import pcap
import stats

# Parameters
log_file = "logfile.log"
pcap_file = "dropped_packets.pcap"
config_file = "config.json"

# Parameter that controls the packet dropping policy:
# 0: only drop the packet;
# 1: drop the packet and send a RST packet to kill the connection;
# 2: drop the packet and send a ACK packet to continue the connection.
dropping_policy = 1

# Checking root privileges
if not utils.is_root():
    print("You need root privileges to run this application!")
    exit(-1)

# Checking debug flag status (-d or --debug)
debug = utils.is_debug()
if debug:
    print("Debug mode detected\n")

# Retrieving config
queue_number, rules, filtering_direction = utils.read_config(config_file)

# Indispensable objects instantiation
log = mylog.Log(log_file)
log.uplog("Starting ips-cc")
shield = my_analysis.Shield(rules, log)
handling = packet_handling.PacketHandling(log, shield, filtering_direction,
                                          debug, dropping_policy)

# Optional objects instantiation: comment them to disable
statistics = stats.Stats(log, handling)
pcap_exporter = pcap.PCAP(log, handling, pcap_file)

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
