import pyshark

def gather_online_activities(pcap_file):
    # Open the PCAP file
    cap = pyshark.FileCapture(pcap_file)

    # Dictionary to store IP addresses and their associated activities
    ip_activities = {}

    # Iterate through each packet in the capture file
    for pkt in cap:
        if "IP" in pkt:
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst

            # Check if source IP address has any online activity
            if ip_src not in ip_activities:
                ip_activities[ip_src] = []

            # Check if destination IP address has any online activity
            if ip_dst not in ip_activities:
                ip_activities[ip_dst] = []

            # Extract the activity details (protocol, port, etc.) from the packet
            activity = {
                "protocol": pkt.transport_layer,
                "src_port": pkt[pkt.transport_layer].srcport,
                "dst_port": pkt[pkt.transport_layer].dstport,
                "timestamp": pkt.sniff_time.strftime("%Y-%m-%d %H:%M:%S")  # Convert timestamp to desired format
            }

            # Add the activity to the respective IP address
            ip_activities[ip_src].append(activity)
            ip_activities[ip_dst].append(activity)

    # Close the PCAP file
    cap.close()

    return ip_activities

# Provide the path to your PCAP file (test.pcap in this case)
pcap_file_path = "Data to Investigate/test.pcap"

# Call the function to gather online activities
activities = gather_online_activities(pcap_file_path)

# Open the log file in write mode
with open("Logs/OnlineActivities.log", "w") as file:
    # Write the categorized activity data by IP address to the log file
    for ip, activities_list in activities.items():
        file.write(f"For IP Address: {ip}\n")
        for activity in activities_list:
            protocol = activity["protocol"]
            src_port = activity["src_port"]
            dst_port = activity["dst_port"]
            timestamp = activity["timestamp"]

            file.write(f"Protocol: {protocol} and Source Port: {src_port} was used to access Destination Port: {dst_port} at Timestamp: {timestamp}\n")
        file.write("\n")  # Add an empty line for readability between activities of the same IP address
print("Data Saved in Logs/OnlineActivities.log. Note that this file overwrites existing log file.")
