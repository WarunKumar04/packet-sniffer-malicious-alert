import requests
import re
import logging
import configparser
import csv
from scapy.all import sniff, IP, TCP, Raw, DNS, DNSQR
import subprocess
from datetime import datetime

class NetworkSecurityMonitor:
    def __init__(self, config_file="config.ini"):
        self.load_config(config_file)
        self.setup_logging()
        self.update_malicious_websites()  

    def load_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        self.firewall_enabled = config.getboolean("Firewall", "Enabled")

    def setup_logging(self):
        logging.basicConfig(
            filename="network_activity.log", level=logging.INFO,
            format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.alert_logger = logging.getLogger("alert_logger")
        alert_handler = logging.FileHandler("alert_generated.log")
        alert_handler.setLevel(logging.WARNING)
        alert_formatter = logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        alert_handler.setFormatter(alert_formatter)
        self.alert_logger.addHandler(alert_handler)

    def update_malicious_websites(self):
        urls = {
            "OpenPhish": "https://openphish.com/feed.txt",
            "URLHaus": "https://urlhaus.abuse.ch/downloads/text/",
            "MalwareDomains": "https://malwaredomains.com/files/domains.txt",
            "PhishTank": "https://data.phishtank.com/data/online-valid.csv"
        }
        
        self.website_patterns = []

        for source, url in urls.items():
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    if "csv" in url:
                        self.parse_csv(response.text)
                    else:
                        self.parse_text(response.text)
                    print(f"✅ Successfully fetched {source}")
                else:
                    print(f"⚠️ Failed to fetch {source} (Status: {response.status_code})")
            except requests.RequestException as e:
                print(f"⚠️ Error fetching {source}: {e}")

        print(f"🔍 Loaded {len(self.website_patterns)} malicious websites.")

    def parse_text(self, text):
        websites = text.split("\n")
        for site in websites:
            site = site.strip().lower().replace("http://", "").replace("https://", "").replace("www.", "").split('/')[0]
            if site and not site.startswith("#"):
                self.website_patterns.append(re.compile(re.escape(site)))

    def parse_csv(self, csv_text):
        reader = csv.reader(csv_text.splitlines())
        next(reader, None)
        for row in reader:
            if row:
                self.website_patterns.append(re.compile(re.escape(row[1])))

    def detect_http_request(self, packet):
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                log_message = f"[{timestamp}] SRC: {src_ip} → DST: {dst_ip} | DATA: {repr(payload)}"
                logging.info(log_message)  # Log all network activity
                
                for pattern in self.website_patterns:
                    if pattern.search(payload):
                        alert_message = f"🚨 ALERT: Malicious website detected! {pattern.pattern} from {src_ip}"
                        print(alert_message)
                        self.alert_logger.warning(alert_message)
            except Exception:
                pass

    def detect_dns_query(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode().strip(".")
            log_message = f"📡 DNS Query Captured: {domain}"
            logging.info(log_message)  # Log all DNS queries
            
            for pattern in self.website_patterns:
                if pattern.search(domain):
                    alert_message = f"🚨 ALERT: Suspicious DNS Query Detected! {domain}"
                    print(alert_message)
                    self.alert_logger.warning(alert_message)

    def start_monitoring(self):
        try:
            print("🔍 Starting network security monitoring...")
            sniff(filter="tcp port 80 or tcp port 443", prn=self.detect_http_request, store=0)
        except KeyboardInterrupt:
            print("🛑 Stopping network monitoring.")
            logging.info("Stopping network monitoring.")

if __name__ == "__main__":
    monitor = NetworkSecurityMonitor()
    monitor.start_monitoring()
