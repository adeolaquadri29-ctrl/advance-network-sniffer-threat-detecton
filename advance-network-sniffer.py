from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw

from datetime import datetime

from collections import defaultdict

import geoip2.database

import json

# ============================================

# LOAD GEOIP DATABASE

# ============================================

reader = geoip2.database.Reader("GeoLite2-City.mmdb")

# ============================================

# TRACKERS

# ============================================

connection_tracker = defaultdict(int)

icmp_tracker = defaultdict(int)

# ============================================

# SHARED LOGS FOR DASHBOARD

# ============================================

logs = []

# ============================================

# THREAT INTELLIGENCE (BASIC BLACKLIST)

# ============================================

blacklist_ips = [

    "1.1.1.1",

    "185.220.101.1",

    "45.95.147.236"

]

# ============================================

# GEOIP LOOKUP

# ============================================

def get_geo(ip):

    try:

        response = reader.city(ip)

        country = response.country.name

        city = response.city.name

        if city:

            return f"{city}, {country}"

        return country

    except:

        return "Unknown"

# ============================================

# PACKET ANALYSIS FUNCTION

# ============================================

def packet_callback(packet):

    # Ignore packets without IP

    if not packet.haslayer(IP):

        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_layer = packet[IP]

    src_ip = ip_layer.src

    dst_ip = ip_layer.dst

    protocol = "OTHER"

    src_port = "N/A"

    dst_port = "N/A"

    payload = "No Payload"

    payload_type = "Unknown"

    alert = "None"

    # ============================================

    # PROTOCOL DETECTION

    # ============================================

    if packet.haslayer(TCP):

        protocol = "TCP"

        src_port = packet[TCP].sport

        dst_port = packet[TCP].dport

        connection_tracker[src_ip] += 1

    elif packet.haslayer(UDP):

        protocol = "UDP"

        src_port = packet[UDP].sport

        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

        icmp_tracker[src_ip] += 1

    # ============================================

    # DNS DETECTION

    # ============================================

    dns_query = "N/A"

    if packet.haslayer(DNS):

        try:

            dns_query = packet[DNS].qd.qname.decode()

        except:

            dns_query = "Unknown"

    # ============================================

    # PAYLOAD ANALYSIS

    # ============================================

    if packet.haslayer(Raw):

        raw_data = packet[Raw].load

        try:

            payload = raw_data.decode('utf-8', errors='ignore')

            payload = payload[:120]

        except:

            payload = str(raw_data[:60])

        # ============================================

        # PAYLOAD TYPE DETECTION

        # ============================================

        if raw_data.startswith(b'GET'):

            payload_type = "HTTP GET"

        elif raw_data.startswith(b'POST'):

            payload_type = "HTTP POST"

        elif raw_data.startswith(b'HTTP'):

            payload_type = "HTTP Response"

        elif raw_data.startswith(b'SSH'):

            payload_type = "SSH Traffic"

        elif raw_data.startswith(b'\x16\x03'):

            payload_type = "TLS Handshake"

        elif raw_data.startswith(b'\x17\x03'):

            payload_type = "Encrypted TLS Traffic"

        else:

            payload_type = "Unknown"

    # ============================================

    # GEOLOCATION

    # ============================================

    location = get_geo(src_ip)

    # ============================================

    # ATTACK DETECTION

    # ============================================

    # Possible Port Scan

    if connection_tracker[src_ip] > 100:

        alert = "⚠️ Possible Port Scan"

    # Possible ICMP Flood

    if icmp_tracker[src_ip] > 20:

        alert = "⚠️ Possible ICMP Flood"

    # Blacklisted IP Detection

    if src_ip in blacklist_ips:

        alert = "🚨 Blacklisted IP Detected"

    # Suspicious Ports

    suspicious_ports = [22, 23, 3389, 4444]

    if dst_port in suspicious_ports:

        alert = f"⚠️ Suspicious Port Access: {dst_port}"

    # ============================================

    # JSON LOG ENTRY

    # ============================================

    log_entry = {

        "time": timestamp,

        "src_ip": src_ip,

        "dst_ip": dst_ip,

        "src_port": src_port,

        "dst_port": dst_port,

        "protocol": protocol,

        "payload_type": payload_type,

        "payload": payload,

        "dns_query": dns_query,

        "location": location,

        "alert": alert

    }

    # ============================================

    # CLEAN TERMINAL OUTPUT

    # ============================================

    print("\n" + "="*60)

    print(f"TIME: {timestamp}")

    print(f"SRC IP: {src_ip}")

    print(f"DST IP: {dst_ip}")

    print(f"SRC PORT: {src_port}")

    print(f"DST PORT: {dst_port}")

    print(f"PROTOCOL: {protocol}")

    print(f"PAYLOAD TYPE: {payload_type}")

    print(f"DNS QUERY: {dns_query}")

    print(f"LOCATION: {location}")

    print(f"ALERT: {alert}")

    print("="*60)

    # ============================================

    # SAVE TO JSON FILE

    # ============================================

    with open("sniffer_log.json", "a") as f:

        json.dump(log_entry, f)

        f.write("\n")

    # ============================================

    # STORE FOR FLASK DASHBOARD

    # ============================================

    logs.append(log_entry)

# ============================================

# START SNIFFER

# ============================================

def start_sniffer():

    print("\n🚀 Advanced Network Sniffer Started...\n")

    sniff(

        prn=packet_callback,

        filter="ip",

        store=False

  )
