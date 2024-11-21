import scapy.all as scapy
import dns.resolver
import socket

def get_actual_ip(domain):
    """Get the actual IP address of the domain using DNS resolver"""
    try:
        answer = dns.resolver.resolve(domain, 'A')
        return answer[0].to_text()
    except Exception as e:
        print(f"Error resolving domain {domain}: {e}")
        return None

def sniff_packets(interface):
    """Sniff DNS packets and detect possible DNS spoofing"""
    print(f"Starting to sniff packets on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    """Process the sniffed packet"""
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if packet.haslayer(scapy.DNS):
            dns_query = packet[scapy.DNS].qd
            if dns_query:
                domain = dns_query.qname.decode()
                print(f"DNS query for domain: {domain} from IP: {ip_src}")

                # Get the actual IP from DNS resolution
                actual_ip = get_actual_ip(domain)
                if actual_ip:
                    # Check if the packet's DNS response IP matches the actual IP
                    if packet.haslayer(scapy.DNSRR):
                        dns_answer_ip = packet[scapy.DNSRR].rdata.decode()
                        print(f"Resolved IP from DNS: {actual_ip} | DNS Response IP: {dns_answer_ip}")
                        if actual_ip != dns_answer_ip:
                            print(f"[!] Potential DNS Spoofing detected! {domain} -> Actual IP: {actual_ip}, Response IP: {dns_answer_ip}")
                        else:
                            print(f"[+] DNS query for {domain} resolved correctly.")
                else:
                    print(f"[!] Could not resolve actual IP for {domain}")
            else:
                print("[*] No DNS query detected in packet.")
        else:
            print("[*] No DNS layer in packet.")

# Run the tool
if __name__ == "__main__":
    interface = input("Enter network interface (e.g., eth0, wlan0): ")
    sniff_packets(interface)
