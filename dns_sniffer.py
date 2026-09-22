#!/usr/bin/env python3

import scapy.all as scapy


def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()

        exclude_keywords = ["google", "cloud", "bing", "static"]
        if domain not in domain_seen and not any(keyword in domain for keyword in exclude_keywords):
            domain_seen.add(domain)
            print(f"[+] Dominio: {domain}")
    


def main():
    global domain_seen
    domain_seen = set()
    interface="wlp1s0"
    print(f"\n[+] Interceptando paquetes de la maquina victima")
    scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)


if __name__ == '__main__':
    main()
