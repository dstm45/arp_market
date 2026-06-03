#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Script 3 : Sniffer complet (Écoute, Dissection, Double Sauvegarde et Bilan)

import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, PcapWriter

# Compteurs pour le bilan final de la soutenance
compteurs = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0}
pcap_fichier = None
log_fichier = None

def analyser_paquet(packet):
    global pcap_fichier, log_fichier
    
    # 1. Action de capture et sauvegarde brute immédiate
    if pcap_fichier:
        pcap_fichier.write(packet)
        
    # 2. Action d'analyse et dissection réseau
    if packet.haslayer(IP):
        compteurs["Total"] += 1
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "Autre"
        port_info = ""
        
        if packet.haslayer(TCP):
            proto = "TCP"
            compteurs["TCP"] += 1
            port_info = f" | Port {packet[TCP].sport} -> Port {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            proto = "UDP"
            compteurs["UDP"] += 1
            port_info = f" | Port {packet[UDP].sport} -> Port {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            compteurs["ICMP"] += 1

        log_line = f"[{packet.time}] {proto} | {ip_src} -> {ip_dst}{port_info}\n"
        print(log_line.strip()) # Affichage en direct sur Kali
        
        if log_fichier:
            log_fichier.write(log_line)
            log_fichier.flush()

def main():
    global pcap_fichier, log_fichier
    parser = argparse.ArgumentParser(description="Sniffer Réseau Complet L3")
    parser.add_argument("-i", "--interface", required=True, help="Interface (ex: eth0)")
    parser.add_argument("-f", "--filter", default="", help="Filtre BPF (ex: 'tcp port 80')")
    args = parser.parse_args()
    
    try:
        pcap_fichier = PcapWriter("capture.pcap", append=True, sync=True)
        log_fichier = open("capture.log", "a", encoding="utf-8")
        print(f"[*] Écoute et capture superposée en cours sur {args.interface}...")
        
        sniff(iface=args.interface, filter=args.filter, prn=analyser_paquet, store=0)
        
    except KeyboardInterrupt:
        print("\n[*] Interruption utilisateur.")
    finally:
        if pcap_fichier: pcap_fichier.close()
        if log_fichier: log_fichier.close()
        
        # Rapport final
        print("\n" + "="*40 + "\n        BILAN STATISTIQUE FINAL        \n" + "="*40)
        print(f" Paquets TCP : {compteurs['TCP']} | Paquets UDP : {compteurs['UDP']} | Paquets ICMP : {compteurs['ICMP']}")
        print(f" TOTAL IP    : {compteurs['Total']}\n" + "="*40)

if __name__ == "__main__":
    main()
