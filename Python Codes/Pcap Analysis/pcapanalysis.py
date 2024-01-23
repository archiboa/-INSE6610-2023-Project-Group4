from scapy.all import *
import time

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        hops = [packet[IP].src] + [ip.src for ip in packet[IP].payload if ip.haslayer(IP)]
        protocol = packet.lastlayer().name
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(packet.time)))
        length = len(packet)
        info = packet.summary()
        return src_ip, dst_ip, hops, protocol, timestamp, length, info

def remove_repeated_hops(hops):
    unique_hops = []
    prev_hop = None
    for hop in hops:
        if hop != prev_hop:
            unique_hops.append(hop)
            prev_hop = hop
    return unique_hops

def process_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    hop_links = defaultdict(list)
    communication_patterns = defaultdict(set)
    for packet in packets:
        result = analyze_packet(packet)
        if result:
            src_ip, dst_ip, hops, protocol, timestamp, length, info = result
            unique_hops = remove_repeated_hops(hops)
            communication_patterns[(src_ip, dst_ip)].add(protocol)
            hop_links[(src_ip, dst_ip)].append((unique_hops[-1], len(unique_hops), protocol, timestamp, length, info))

    # Export communication patterns to a log file
    log_file = open("communication_patterns.log", "w")
    log_header = "Source IP\tDestination IP\tProtocol\tTime\tLength\tInfo\n"
    log_file.write(log_header)
    for (src_ip, dst_ip), protocols in communication_patterns.items():
        for protocol in protocols:
            hops_details = hop_links[(src_ip, dst_ip)]
            for hop, hop_length, _, timestamp, length, info in hops_details:
                log_entry = f"{src_ip}\t{dst_ip}\t{protocol}\t{timestamp}\t{length}\t{info}\n"
                log_file.write(log_entry)
    log_file.close()

    # Generate hop list file
    hop_list_file = open("hop_list.txt", "w")
    hop_list_header = "Source IP\tDestination IP\tHops\n"
    hop_list_file.write(hop_list_header)
    for (src_ip, dst_ip), hops_details in hop_links.items():
        for hop, _, _, _, _, _ in hops_details:
            hop_list_entry = f"{src_ip}\t{dst_ip}\t{hop}\n"
            hop_list_file.write(hop_list_entry)
    hop_list_file.close()

    print("Data exported to communication_patterns.log and hop_list.txt.")

# Replace 'test.pcap' with the path to your pcap file
process_pcap('test.pcap')
