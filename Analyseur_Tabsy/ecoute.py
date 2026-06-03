#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Script 1 : Écoute passive et analyse des flux en direct

from scapy.all import sniff, IP, TCP, UDP, ICMP

def traiter_flux(packet):
    # On écoute et on isole la couche Réseau (IP)
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "AUTRE"
        ports = ""

        # On identifie le protocole de la couche de Transport
        if packet.haslayer(TCP):
            protocol = "TCP"
            ports = f" | Port {packet[TCP].sport} -> Port {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            ports = f" | Port {packet[UDP].sport} -> Port {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP (Ping)"

        # Affichage instantané du flux intercepté à l'écran
        print(f"[ÉCOUTE] {protocol} : {ip_src} -> {ip_dst}{ports}")

print("[*] Démarrage de l'écoute passive sur eth0... (Faites Ctrl+C pour arrêter)")
# La fonction sniff ouvre le canal d'écoute réseau
sniff(iface="eth0", prn=traiter_flux, store=0)
