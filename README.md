# Packet Sniffer with Phishing Detection  

## Description  
This project is a **Python-based packet sniffer** that monitors network traffic and checks visited websites against a **phishing database**. If a website is detected as suspicious, the program generates an **alert** to warn the user.  

## Features  
- Captures network packets to extract visited URLs  
- Compares URLs against a phishing database (local or API-based)  
- Generates alerts when a phishing site is detected  
- Lightweight and runs in the background  

## How It Works  
1. The program **sniffs network traffic** to capture outgoing HTTP/HTTPS requests.  
2. Extracted URLs are **compared with a phishing database**.  
3. If a match is found, the program **triggers an alert**.  

## Dependencies  
- `scapy` (for packet sniffing)  
- `requests` (if using an online phishing database API)  
- `csv` (if using a local phishing database)  

## Usage  
Run the Python script with administrator privileges:  
```bash
python packet_sniffer.py
```
