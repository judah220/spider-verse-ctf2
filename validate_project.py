#!/usr/bin/env python3
"""
SPIDER-VERSE CTF — Automated Project Validation
================================================
Validates all 5 PCAP captures and challenge metadata.

Usage:
    py -3 validate_project.py

Reports PASS / FAIL for each check.
"""

import sys
import os
import base64
import traceback

# ── Dependency check ───────────────────────────────────────────────────────────
try:
    from scapy.utils import rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw
except ImportError:
    print("[ERROR] Scapy not found. Run:  py -3 -m pip install scapy")
    sys.exit(1)

# ── Expected values ────────────────────────────────────────────────────────────
FLAGS = {
    1: b"FLAG{n3tw0rk_str3am_1s_fun}",
    2: b"FLAG{dns_1s_n0t_just_for_nam3s}",
    3: b"FLAG{p1ng_p4ylo4d_h1d3s_d4t4}",
    4: b"FLAG{p0rt_sc4nn3r_d3t3ct3d}",
    5: b"FLAG{http_f1l3_c4rv1ng_pr0}",
}

PCAP_PATHS = {
    1: "challenges/01_follow_the_stream/stream_capture.pcap",
    2: "challenges/02_dns_exfiltration/dns_exfil.pcap",
    3: "challenges/03_ping_of_secrets/icmp_secret.pcap",
    4: "challenges/04_who_scanned_me/port_scan.pcap",
    5: "challenges/05_http_treasure_hunt/http_transfer.pcap",
}

CHALLENGE_TXT = {
    1: "challenges/01_follow_the_stream/challenge.txt",
    2: "challenges/02_dns_exfiltration/challenge.txt",
    3: "challenges/03_ping_of_secrets/challenge.txt",
    4: "challenges/04_who_scanned_me/challenge.txt",
    5: "challenges/05_http_treasure_hunt/challenge.txt",
}

POINTS = {1: 100, 2: 150, 3: 100, 4: 200, 5: 200}
CATEGORIES = {
    1: "Network Forensics",
    2: "DNS / Network Forensics",
    3: "ICMP / Network Forensics",
    4: "Network Detection / Forensics",
    5: "HTTP / File Carving",
}

# ── Result tracking ────────────────────────────────────────────────────────────
results = []

def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((status, name, detail))
    icon = "✓" if condition else "✗"
    print(f"  [{status}] {icon} {name}")
    if detail and not condition:
        print(f"         → {detail}")
    return condition

def section(title):
    print()
    print(f"─── {title} " + "─" * (55 - len(title)))


# ==============================================================================
# Challenge 1 — TCP Stream
# ==============================================================================
def validate_ch1():
    section("Challenge 1: Peter Parker's Packet Trail (TCP stream)")
    path = PCAP_PATHS[1]

    if not check("PCAP file exists and is non-empty",
                 os.path.exists(path) and os.path.getsize(path) > 0,
                 f"{path} missing or empty"):
        return

    pkts = rdpcap(path)
    check("Contains packets", len(pkts) > 0, "No packets found")

    # Check for TCP layer on port 9001
    tcp_pkts = [p for p in pkts if TCP in p and
                (p[TCP].dport == 9001 or p[TCP].sport == 9001)]
    check("TCP packets on port 9001 present", len(tcp_pkts) > 0)

    # Check for SYN packet
    syn_pkts = [p for p in tcp_pkts if p[TCP].flags & 0x02 and not (p[TCP].flags & 0x10)]
    check("SYN packet present (handshake)", len(syn_pkts) > 0)

    # Check flag in Raw payload
    flag = FLAGS[1]
    flag_pkts = [p for p in pkts if Raw in p and flag in bytes(p[Raw])]
    check("Flag found in TCP payload", len(flag_pkts) > 0,
          f"'{flag.decode()}' not found in any Raw payload")

    # Check source/dest IPs
    src_correct = any(IP in p and p[IP].src == "192.0.2.10" for p in pkts)
    dst_correct = any(IP in p and p[IP].dst == "198.51.100.20" for p in pkts)
    check("Source IP 192.0.2.10 present", src_correct)
    check("Destination IP 198.51.100.20 present", dst_correct)


# ==============================================================================
# Challenge 2 — DNS Exfiltration
# ==============================================================================
def validate_ch2():
    section("Challenge 2: The Green Goblin's DNS Trap (DNS exfil)")
    path = PCAP_PATHS[2]

    if not check("PCAP file exists and is non-empty",
                 os.path.exists(path) and os.path.getsize(path) > 0):
        return

    pkts = rdpcap(path)
    check("Contains packets", len(pkts) > 0)

    # Filter DNS query packets
    dns_pkts = [p for p in pkts if DNS in p and p[DNS].qr == 0]
    check("DNS query packets present", len(dns_pkts) > 0)

    # Extract subdomains from queries
    labels_with_idx = []
    for p in dns_pkts:
        try:
            qname = p[DNS].qd.qname.decode(errors="ignore")
            # Format: c00-<chunk>.malicious.example.com.
            if "malicious.example.com" in qname:
                # Extract the first label, e.g. c00-RkxBR3...
                first_label = qname.split(".")[0]
                if first_label.startswith("c") and "-" in first_label:
                    idx_str, chunk = first_label[1:].split("-", 1)
                    labels_with_idx.append((int(idx_str), chunk))
        except Exception:
            pass

    check("DNS exfil labels found (c##-<data> format)", len(labels_with_idx) > 0,
          "No labels matching 'c##-<data>.malicious.example.com' found")

    if labels_with_idx:
        # Sort by index and reassemble
        labels_with_idx.sort(key=lambda x: x[0])
        reassembled = "".join(chunk for _, chunk in labels_with_idx)
        try:
            padding = 4 - (len(reassembled) % 4) if len(reassembled) % 4 else 0
            decoded = base64.b64decode(reassembled + "=" * padding)
            flag_match = decoded == FLAGS[2]
            check("Reassembled Base64 decodes to correct flag", flag_match,
                  f"Got: {decoded}  Expected: {FLAGS[2]}")
        except Exception as e:
            check("Reassembled Base64 decodes to correct flag", False, str(e))


# ==============================================================================
# Challenge 3 — ICMP Hidden Payload
# ==============================================================================
def validate_ch3():
    section("Challenge 3: Electro's Hidden Signal (ICMP payload)")
    path = PCAP_PATHS[3]

    if not check("PCAP file exists and is non-empty",
                 os.path.exists(path) and os.path.getsize(path) > 0):
        return

    pkts = rdpcap(path)
    check("Contains packets", len(pkts) > 0)

    icmp_pkts = [p for p in pkts if ICMP in p]
    check("ICMP packets present", len(icmp_pkts) > 0)

    # Check for echo requests (type 8) with flag in payload
    flag = FLAGS[3]
    req_with_flag = [p for p in icmp_pkts
                     if p[ICMP].type == 8 and Raw in p and flag in bytes(p[Raw])]
    check("Flag found in ICMP echo request payload", len(req_with_flag) > 0,
          f"'{flag.decode()}' not in ICMP echo request data")

    src_correct = any(IP in p and p[IP].src == "192.0.2.15" for p in icmp_pkts)
    dst_correct = any(IP in p and p[IP].dst == "198.51.100.25" for p in icmp_pkts)
    check("Source IP 192.0.2.15 present", src_correct)
    check("Destination IP 198.51.100.25 present", dst_correct)

    # Check replies
    replies = [p for p in icmp_pkts if p[ICMP].type == 0]
    check("ICMP echo replies present", len(replies) > 0)


# ==============================================================================
# Challenge 4 — SYN Scan + Port 1337 banner
# ==============================================================================
def validate_ch4():
    section("Challenge 4: Mysterio's Recon Network (SYN scan)")
    path = PCAP_PATHS[4]

    if not check("PCAP file exists and is non-empty",
                 os.path.exists(path) and os.path.getsize(path) > 0):
        return

    pkts = rdpcap(path)
    check("Contains packets", len(pkts) > 0)

    # SYN probes from attacker
    syn_probes = [p for p in pkts
                  if TCP in p and IP in p
                  and p[IP].src == "192.0.2.50"
                  and p[TCP].flags & 0x02
                  and not (p[TCP].flags & 0x10)]
    check("SYN probes from 192.0.2.50 present", len(syn_probes) > 0)
    check("Multiple ports scanned (≥10 SYN probes)", len(syn_probes) >= 10,
          f"Only {len(syn_probes)} SYN probes found")

    # Port 1337 specifically scanned
    scan_dports = {p[TCP].dport for p in syn_probes}
    check("Port 1337 included in scan", 1337 in scan_dports,
          f"Port 1337 not in scanned ports: {sorted(scan_dports)[:20]}...")

    # Banner on port 1337 contains flag
    flag = FLAGS[4]
    banner_pkts = [p for p in pkts
                   if Raw in p and TCP in p
                   and (p[TCP].sport == 1337 or p[TCP].dport == 1337)
                   and flag in bytes(p[Raw])]
    check("Flag found in port 1337 service banner", len(banner_pkts) > 0,
          f"'{flag.decode()}' not found in port 1337 traffic")

    # Target IP
    target_ok = any(IP in p and p[IP].dst == "198.51.100.10" for p in syn_probes)
    check("Target IP 198.51.100.10 present", target_ok)


# ==============================================================================
# Challenge 5 — HTTP File Carving
# ==============================================================================
def validate_ch5():
    section("Challenge 5: Doc Ock's Stolen File (HTTP carving)")
    path = PCAP_PATHS[5]

    if not check("PCAP file exists and is non-empty",
                 os.path.exists(path) and os.path.getsize(path) > 0):
        return

    pkts = rdpcap(path)
    check("Contains packets", len(pkts) > 0)

    tcp_8080 = [p for p in pkts if TCP in p and
                (p[TCP].sport == 8080 or p[TCP].dport == 8080)]
    check("TCP packets on port 8080 present", len(tcp_8080) > 0)

    # HTTP GET request
    get_pkts = [p for p in pkts if Raw in p and b"GET /secret_notes.txt" in bytes(p[Raw])]
    check("HTTP GET /secret_notes.txt request present", len(get_pkts) > 0)

    # HTTP 200 OK response
    ok_pkts = [p for p in pkts if Raw in p and b"HTTP/1.1 200 OK" in bytes(p[Raw])]
    check("HTTP 200 OK response present", len(ok_pkts) > 0)

    # Content-Type header
    ct_pkts = [p for p in pkts if Raw in p and b"Content-Type: text/plain" in bytes(p[Raw])]
    check("Content-Type: text/plain header present", len(ct_pkts) > 0)

    # Content-Length header
    cl_pkts = [p for p in pkts if Raw in p and b"Content-Length:" in bytes(p[Raw])]
    check("Content-Length header present", len(cl_pkts) > 0)

    # Flag in response body
    flag = FLAGS[5]
    flag_pkts = [p for p in pkts if Raw in p and flag in bytes(p[Raw])]
    check("Flag found in HTTP response body", len(flag_pkts) > 0,
          f"'{flag.decode()}' not found in HTTP response")


# ==============================================================================
# Metadata Checks — Participant safety
# ==============================================================================
def validate_metadata():
    section("Metadata Safety Checks")

    for num, path in CHALLENGE_TXT.items():
        if not os.path.exists(path):
            check(f"challenge.txt #{num} exists", False, f"Missing: {path}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        flag_str = FLAGS[num].decode()
        check(f"challenge.txt #{num} does NOT contain the flag",
              flag_str not in content,
              f"FLAG LEAK DETECTED in {path}!")

    # Check that PCAP files are present and referenced
    for num, pcap in PCAP_PATHS.items():
        check(f"PCAP attachment #{num} exists at expected path",
              os.path.exists(pcap) and os.path.getsize(pcap) > 0)


# ==============================================================================
# Main
# ==============================================================================
def main():
    print()
    print("=" * 65)
    print("  SPIDER-VERSE CTF — Automated Validation")
    print("=" * 65)

    validate_ch1()
    validate_ch2()
    validate_ch3()
    validate_ch4()
    validate_ch5()
    validate_metadata()

    print()
    print("=" * 65)
    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] == "FAIL")
    total  = len(results)
    print(f"  RESULTS: {passed}/{total} checks PASSED  |  {failed} FAILED")
    print("=" * 65)

    if failed == 0:
        print()
        print("  ✓ ALL CHECKS PASSED — Project is ready for deployment!")
        print()
    else:
        print()
        print("  ✗ Some checks failed. Review output above and fix issues.")
        print("    Run  py -3 generate_pcaps.py  first if PCAPs are missing.")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
