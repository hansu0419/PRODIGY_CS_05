from scapy.all import sniff, IP, Raw

def packet_analysis(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        payload = packet[Raw].load if packet.haslayer(Raw) else b""
        payload_str = payload.decode(errors='replace')

        print(f"Source: {ip_layer.src} | Dest: {ip_layer.dst} | Protocol: {ip_layer.proto} | Payload: {payload_str[:50]}")

sniff(filter="ip", prn=packet_analysis, store=0)
