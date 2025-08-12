import os
from dotenv import load_dotenv
from core.osint_correlator import OSINTCorrelator

# Carica variabili da .env
load_dotenv()

abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
shodan_key = os.getenv("SHODAN_KEY")
virustotal_key = os.getenv("VIRUSTOTAL_KEY")

correlator = OSINTCorrelator(abuseipdb_key, shodan_key, virustotal_key)

# IP da testare (puoi usare IP noti come Google DNS o IP compromessi trovati nei log)
ip = "8.8.8.8"

print("\n===== TEST OSINT =====")
print(f"Testing IP: {ip}\n")

abuse_result = correlator.query_abuseipdb(ip)
print("🔍 AbuseIPDB result:")
print(abuse_result)

shodan_result = correlator.query_shodan(ip)
print("\n🛰️ Shodan result:")
print(shodan_result)

virustotal_result = correlator.query_virustotal(ip)
print("\n🦠 VirusTotal result:")
print(virustotal_result)
