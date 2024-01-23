import pyshark
import geoip2.database
import requests
from datetime import datetime
import subprocess
import os

# Function to get geolocation data
def get_geolocation(ip):
    reader = geoip2.database.Reader('Resources/GeoLite2-Country.mmdb')
    try:
        response = reader.country(ip)
        return response.country.name
    except geoip2.errors.AddressNotFoundError:
        return 'Unknown'

# Function to get ISP data
def get_isp(ip):
    url = f"https://ipinfo.io/{ip}/org"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip()
    else:
        return 'Unknown'

# Function to perform online activity analysis (placeholder)
def analyze_online_activity(ip):
    # Perform your analysis here based on the IP
    return 'Activity analysis result'

# Function to check legal requests (placeholder)
def check_legal_requests(ip):
    # Perform your checks here based on the IP
    return 'Legal request check result'

# Function to perform user profiling (placeholder)
def perform_user_profiling(ip):
    # Perform your profiling here based on the IP
    return 'User profiling result'

# Function to perform security checks (placeholder)
def perform_security_checks(ip):
    # Perform your security checks here based on the IP
    return 'Security check result'

# Path to the PCAP file
pcap_file = 'Data to Investigate/test.pcap'

# Open the PCAP file
capture = pyshark.FileCapture(pcap_file)

# Store unique IPs and their type (source, destination, or hop)
ip_types = {}

# Iterate over packets
for packet in capture:
    if 'ip' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        # Add source IP to unique IPs and mark it as source IP
        if src_ip not in ip_types:
            ip_types[src_ip] = {'Type': 'Source IP', 'HopCount': 0}

        # Add destination IP to unique IPs and mark it as destination IP
        if dst_ip not in ip_types:
            ip_types[dst_ip] = {'Type': 'Destination IP', 'HopCount': 0}

        # Check if 'hops' attribute is present and add hop IPs to unique IPs
        if hasattr(packet.ip, 'hops') and packet.ip.hops:
            hop_count = len(packet.ip.hops.split(','))
            for hop in packet.ip.hops.split(','):
                hop = hop.strip()
                if hop and hop not in ip_types:
                    ip_types[hop] = {'Type': 'Hop IP', 'HopCount': hop_count}

# Close the capture
capture.close()

# Open the log file to save the gathered data
with open("Logs/GatherAllData.log", "a") as log_file:
    # Write the timestamp to the log file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write(f"\n-----Timestamp: {timestamp}-----\n")
    log_file.write(f"----------------------\n")
    print("Gathering Geolocation...")
    print("Gathering ISP details...")

    # Iterate over the unique IPs and gather data for each category
    for ip in ip_types:
        geolocation = get_geolocation(ip)
        isp = get_isp(ip)
        online_activity = analyze_online_activity(ip)
        legal_requests = check_legal_requests(ip)
        user_profiling = perform_user_profiling(ip)
        security_checks = perform_security_checks(ip)

        # Write log format for unique IPs and hop IPs to the log file
        log_file.write(f"IP: {ip}\n")
        log_file.write(f"Type: {ip_types[ip]['Type']}\n")
        log_file.write(f"Hop Count: {ip_types[ip]['HopCount']}\n")
        log_file.write(f"Geolocation: {geolocation}\n")
        log_file.write(f"ISP: {isp}\n")
        log_file.write("-" * 50 + "\n")

print("Data saved in Logs/GatherAllData.log")
print("What do you need?\nPress 1 for Online Activities\nPress 2 for Legal Requests\nPress 3 for User Profiling\nPress 4 for Security Checks\n")
data = input()
if int(data)==1:
    python_program_path = "getdetailsusingip.py"  # Replace with the path to your Python program
    subprocess.run(['python3', python_program_path])
elif data==2:
    print("Legal requests:\n")
elif data==3:
    print("Legal requests:\n")
elif data==4:
    print("Legal requests:\n")
else:
    print("Invalid input\n")
