#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Script 2 : Capture et stockage brut (Wireshark)

from scapy.all import sniff, PcapWriter

print("[*] Initialisation du fichier de stockage 'capture_brute.pcap'...")
# Ouverture du fichier de persistance sur le disque
pcap_writer = PcapWriter("capture_brute.pcap", append=True, sync=True)

def capturer_et_sauvegarder(packet):
    # Capture et écriture immédiate du paquet brut
    pcap_writer.write(packet)
    print(".", end="", flush=True) # Indicateur visuel de capture

try:
    print("[*] Capture et enregistrement en cours sur eth0... (Faites Ctrl+C pour arrêter)")
    sniff(iface="eth0", prn=capturer_et_sauvegarder, store=0)
except KeyboardInterrupt:
    print("\n[*] Arrêt de la capture.")
finally:
    # Fermeture propre du fichier pour éviter toute corruption
    pcap_writer.close()
    print("[*] Fichier 'capture_brute.pcap' sauvegardé avec succès.")
