import subprocess
import sys
import os
import math
from collections import Counter

class PCAPAnalyzer:

    def __init__(self, pcap_file):
        self.pcap = pcap_file

    def run_tshark(self, command):
        try:
            result = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.DEVNULL
            )
            return result.decode().strip()
        except:
            return ""

    # =============================
    # NETWORK PERFORMANCE
    # =============================

    def total_packets(self):
        cmd = f"tshark -r {self.pcap} | wc -l"
        return self.run_tshark(cmd)

    def top_talker(self):
        cmd = f"tshark -r {self.pcap} -T fields -e ip.src"
        output = self.run_tshark(cmd)
        ips = [ip for ip in output.split("\n") if ip]
        if not ips:
            return "N/A"
        return Counter(ips).most_common(1)[0][0]

    def top_protocol(self):
        cmd = f"tshark -r {self.pcap} -T fields -e _ws.col.Protocol"
        output = self.run_tshark(cmd)
        protos = [p for p in output.split("\n") if p]
        if not protos:
            return "N/A"
        return Counter(protos).most_common(1)[0][0]

    def retransmissions(self):
        cmd = f"tshark -r {self.pcap} -Y tcp.analysis.retransmission | wc -l"
        return self.run_tshark(cmd)

    def bandwidth(self):
        cmd = f"tshark -r {self.pcap} -T fields -e frame.len"
        output = self.run_tshark(cmd)
        sizes = [int(x) for x in output.split("\n") if x.isdigit()]
        total = sum(sizes)
        return f"{round(total/1024,2)} KB"

    # =============================
    # ATTACK DETECTION
    # =============================

    def detect_port_scan(self):
        cmd = f"tshark -r {self.pcap} -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e tcp.dstport"
        output = self.run_tshark(cmd)

        scan_map = {}
        for line in output.split("\n"):
            if line:
                parts = line.split()
                if len(parts) == 2:
                    src, port = parts
                    scan_map.setdefault(src, set()).add(port)

        for src in scan_map:
            if len(scan_map[src]) > 20:
                return "YES"
        return "NO"

    def detect_syn_flood(self):
        cmd = f"tshark -r {self.pcap} -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' | wc -l"
        count = int(self.run_tshark(cmd) or 0)
        return "YES" if count > 100 else "NO"

    def detect_arp_spoof(self):
        cmd = f"tshark -r {self.pcap} -Y arp -T fields -e arp.src.proto_ipv4 -e eth.src"
        output = self.run_tshark(cmd)

        arp_map = {}
        for line in output.split("\n"):
            if line:
                ip, mac = line.split()
                arp_map.setdefault(ip, set()).add(mac)

        for ip in arp_map:
            if len(arp_map[ip]) > 1:
                return "YES"
        return "NO"

    def calculate_entropy(self, string):
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log2(p) for p in prob])
        return entropy

    def detect_dns_tunneling(self):
        cmd = f"tshark -r {self.pcap} -Y dns -T fields -e dns.qry.name"
        output = self.run_tshark(cmd)

        queries = [q for q in output.split("\n") if q]

        if len(queries) < 50:
            return "NO"

        long_queries = [q for q in queries if len(q) > 30]

        high_entropy = 0
        for q in long_queries:
            sub = q.split(".")[0]
            if len(sub) > 20:
                if self.calculate_entropy(sub) > 3.5:
                    high_entropy += 1

        if high_entropy > 30:
            return "YES"

        return "NO"

    def detect_bruteforce(self):
        cmd = f"tshark -r {self.pcap} -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src"
        output = self.run_tshark(cmd)

        ips = [ip for ip in output.split("\n") if ip]
        counter = Counter(ips)

        for ip in counter:
            if counter[ip] > 50:
                return "YES"
        return "NO"


# =============================
# MAIN
# =============================

def main():
    print("==== PCAP Analyzer CLI Tool ====")
    pcap = input("Enter PCAP file path: ")

    if not os.path.exists(pcap):
        print("File not found!")
        sys.exit()

    analyzer = PCAPAnalyzer(pcap)

    print("\n==============================")
    print("PCAP ANALYSIS REPORT")
    print("==============================\n")

    print("Network Performance:")
    print("- Total Packets:", analyzer.total_packets())
    print("- Top Talker:", analyzer.top_talker())
    print("- Top Protocol:", analyzer.top_protocol())
    print("- Avg RTT: N/A")
    print("- Retransmissions:", analyzer.retransmissions())
    print("- Bandwidth:", analyzer.bandwidth())

    print("\nAttack Detection:")
    print("- Port Scan:", analyzer.detect_port_scan())
    print("- SYN Flood:", analyzer.detect_syn_flood())
    print("- ARP Spoofing:", analyzer.detect_arp_spoof())
    print("- DNS Tunneling:", analyzer.detect_dns_tunneling())
    print("- Brute Force:", analyzer.detect_bruteforce())


if __name__ == "__main__":
    main()
