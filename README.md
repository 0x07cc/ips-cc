[English](README.md) | [Italian](README.it.md)
# A mini-IPS for CC
A program that has the purpose to block TCP/UDP data packets containing a given pattern.  
It uses nf_queue, available in the Linux Kernel.  
It can be programmed to block incoming or outgoing traffic just by editing the iptables/nftables rule.  
It doesn't handle IPv6 packets.  
It can also be programmed to send TCP RST/ACK replies to dropped packets in order to kill/continue the connection.

## Arch Linux: Quick Start (iptables)
Installing:
1. Make sure to have Python > 3.7
1. Install compile tools: `sudo pacman -S base-devel python-setuptools cython`
1. Install git: `sudo pacman -S git`
1. Make sure to have iptables
1. Install libnetfilter_queue: `sudo pacman -S libnetfilter_queue`
1. Install NetfilterQueue:   `git clone https://github.com/oremanj/python-netfilterqueue`  
`cd python-netfilterqueue`  
`sudo python3 setup.py install`  
1. Append the iptables rule: `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py -d`  (-d stands for debug)

## Alpine Linux: Quick Start (nftables)
Installing (as root):
1. Install compile tools: `apk add cython py3-setuptools gcc python3-dev musl-dev linux-headers`
1. Install git: `apk add git`
1. Install and start nftables: `apk add nftables; rc-service nftables start`
1. Install libnetfilter_queue: `apk add libnetfilter_queue libnetfilter_queue-dev libnfnetlink-dev`
1. Install NetfilterQueue:   `git clone https://github.com/oremanj/python-netfilterqueue`  
`cd python-netfilterqueue`  
`python3 setup.py install`  
1. Append a nftables rule like `tcp dport 2222 queue to 33` in an input chain, where 2222 is the listening port of a server application to protect
1. Start the script as root: `sudo ./main.py -d`  (-d stands for debug)

## iptables example rules
1. Default: Block incoming traffic from clients to an application running on the machine (server): `sudo iptables -A INPUT -j NFQUEUE --queue-num 33 -p tcp --dport 2222`
1. Block outgoing traffic from an application running on the machine (server) to clients: `sudo iptables -A OUTPUT -j NFQUEUE --queue-num 33 -p tcp --sport 2222`

## Debug mode
In debug mode the program will print on screen each packet it handles and save it in a .pcap file.  
To activate it: `sudo ./main.py -d` or `sudo ./main.py --debug`
