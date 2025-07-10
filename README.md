🔒 ICMP Packet Spoofing & Detection Tool (C)
This project is a two-part system written in C that demonstrates both spoofed ICMP packet generation and real-time spoof detection by analyzing network traffic at the raw socket level.

🧨 Part 1: ICMP Packet Spoofer
This component generates and sends spoofed ICMP echo requests (a.k.a. pings) to a target IP using forged source addresses and manipulated TTL values.

Key Features:

Uses raw sockets to craft custom IP and ICMP headers.

Spoofs the source IP with random addresses.

Sends multiple invalid packets with varying TTLs.

Ends by sending a legitimate packet from the local IP for comparison.

Purpose: Simulates malicious activity (e.g., IP spoofing) to test detection systems.

🛡️ Part 2: ICMP Packet Spoof Detector
This component listens for incoming ICMP echo requests and attempts to detect spoofed packets using TTL and IP ID heuristics.

Detection Heuristics:

TTL Analysis: Checks if observed TTL values are within expected ranges (e.g., 64 for Linux, 128 for Windows).

IP ID Consistency: Tracks IP ID progression from each source to detect anomalies (e.g., non-sequential jumps).

Local IP Bypass: Handles localhost traffic as a special case.

Live Console Output:
Displays the IP, TTL, and ID of each packet with [OK] or [BAD] tags, and prints “SPOOF DETECTED” warnings when anomalies are found.

⚙️ System Requirements
Must be run as root (raw socket permissions).

Requires a Linux environment (uses netinet/ip.h, icmp.h, and raw sockets).

🧠 Use Cases
Network security learning projects

Intrusion detection system (IDS) simulations

Packet structure and spoofing behavior analysis

Real-world example of protocol-level inspection without third-party libraries
