#!/usr/bin/env python3
"""
SPIDER-VERSE CTF — Network Forensics PCAP Generator
====================================================
Generates five PCAP files for network forensics challenges using Scapy.

Requirements:
    py -3 -m pip install scapy

Usage:
    py -3 generate_pcaps.py

All packets are constructed OFFLINE using Scapy's packet library.
No live scanning, no network access, no root/admin privileges needed.
IP addresses are from IETF documentation ranges (RFC 5737):
  192.0.2.0/24  — TEST-NET-1
  198.51.100.0/24 — TEST-NET-2
"""

import sys
import os
import base64
import struct
import datetime

# ── Dependency Check ───────────────────────────────────────────────────────────
def check_dependencies():
    try:
        import scapy  # noqa: F401
    except ImportError:
        print("[ERROR] Scapy is not installed.")
        print("        Install it with:  py -3 -m pip install scapy")
        sys.exit(1)

check_dependencies()

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw
from scapy.utils import wrpcap

# ── Output Directories ─────────────────────────────────────────────────────────
CHALLENGES = {
    1: "challenges/01_follow_the_stream",
    2: "challenges/02_dns_exfiltration",
    3: "challenges/03_ping_of_secrets",
    4: "challenges/04_who_scanned_me",
    5: "challenges/05_http_treasure_hunt",
}

# ── Flags (organizer-side — NOT placed in participant challenge.txt files) ─────
FLAGS = {
    1: b"FLAG{n3tw0rk_str3am_1s_fun}",
    2: b"FLAG{dns_1s_n0t_just_for_nam3s}",
    3: b"FLAG{p1ng_p4ylo4d_h1d3s_d4t4}",
    4: b"FLAG{p0rt_sc4nn3r_d3t3ct3d}",
    5: b"FLAG{http_f1l3_c4rv1ng_pr0}",
}

# ── Helpers ────────────────────────────────────────────────────────────────────
BASE_TIME = 1700000000.0  # deterministic epoch anchor

def ensure_dirs():
    for path in CHALLENGES.values():
        os.makedirs(path, exist_ok=True)

def pcap_path(challenge_num, filename):
    return os.path.join(CHALLENGES[challenge_num], filename)


# ==============================================================================
# CHALLENGE 1 — Follow the Stream (TCP conversation on port 9001)
# Mission: Peter Parker's Packet Trail
# Flag: FLAG{n3tw0rk_str3am_1s_fun}
# ==============================================================================
def generate_challenge_1():
    """
    Creates a complete TCP conversation between 192.0.2.10 → 198.51.100.20:9001.
    The plaintext flag is sent in the client-to-server DATA packet.
    Recovery: Wireshark → right-click a packet → Follow → TCP Stream
    """
    print("[1/5] Generating Peter Parker's Packet Trail (TCP stream)...")

    src = "192.0.2.10"
    dst = "198.51.100.20"
    sport = 54321          # ephemeral client port
    dport = 9001           # challenge port
    flag  = FLAGS[1]

    # Starting sequence numbers
    client_seq = 1000
    server_seq = 5000

    packets = []
    t = BASE_TIME

    # ── 3-Way Handshake ────────────────────────────────────────────────────────
    # SYN
    syn = (IP(src=src, dst=dst, ttl=64) /
           TCP(sport=sport, dport=dport, flags="S",
               seq=client_seq, ack=0, window=65535))
    syn.time = t; t += 0.001
    packets.append(syn)

    # SYN-ACK
    syn_ack = (IP(src=dst, dst=src, ttl=64) /
               TCP(sport=dport, dport=sport, flags="SA",
                   seq=server_seq, ack=client_seq + 1, window=65535))
    syn_ack.time = t; t += 0.001
    packets.append(syn_ack)

    # ACK
    ack = (IP(src=src, dst=dst, ttl=64) /
           TCP(sport=sport, dport=dport, flags="A",
               seq=client_seq + 1, ack=server_seq + 1, window=65535))
    ack.time = t; t += 0.001
    packets.append(ack)

    # ── Application Data ───────────────────────────────────────────────────────
    # Client → Server: greeting
    greeting = b"HELLO SPIDER-VERSE-CTF SERVER\r\n"
    psh_greet = (IP(src=src, dst=dst, ttl=64) /
                 TCP(sport=sport, dport=dport, flags="PA",
                     seq=client_seq + 1, ack=server_seq + 1) /
                 Raw(load=greeting))
    psh_greet.time = t; t += 0.002
    packets.append(psh_greet)

    # Server ACK
    srv_ack1 = (IP(src=dst, dst=src, ttl=64) /
                TCP(sport=dport, dport=sport, flags="A",
                    seq=server_seq + 1, ack=client_seq + 1 + len(greeting)))
    srv_ack1.time = t; t += 0.001
    packets.append(srv_ack1)

    # Server → Client: challenge prompt
    prompt = b"READY. SEND SECRET:\r\n"
    srv_data = (IP(src=dst, dst=src, ttl=64) /
                TCP(sport=dport, dport=sport, flags="PA",
                    seq=server_seq + 1, ack=client_seq + 1 + len(greeting)) /
                Raw(load=prompt))
    srv_data.time = t; t += 0.002
    packets.append(srv_data)

    # Client ACK
    cli_ack1 = (IP(src=src, dst=dst, ttl=64) /
                TCP(sport=sport, dport=dport, flags="A",
                    seq=client_seq + 1 + len(greeting),
                    ack=server_seq + 1 + len(prompt)))
    cli_ack1.time = t; t += 0.001
    packets.append(cli_ack1)

    # Client → Server: FLAG payload  <<<< HIDDEN FLAG >>>>
    cli_seq_after = client_seq + 1 + len(greeting)
    srv_ack_val   = server_seq + 1 + len(prompt)
    payload = flag + b"\r\n"
    psh_flag = (IP(src=src, dst=dst, ttl=64) /
                TCP(sport=sport, dport=dport, flags="PA",
                    seq=cli_seq_after, ack=srv_ack_val) /
                Raw(load=payload))
    psh_flag.time = t; t += 0.002
    packets.append(psh_flag)

    # Server → Client: confirmation
    confirm = b"SECRET RECEIVED. THANK YOU.\r\n"
    srv_confirm = (IP(src=dst, dst=src, ttl=64) /
                   TCP(sport=dport, dport=sport, flags="PA",
                       seq=srv_ack_val, ack=cli_seq_after + len(payload)) /
                   Raw(load=confirm))
    srv_confirm.time = t; t += 0.002
    packets.append(srv_confirm)

    # ── Teardown (FIN-ACK exchange) ────────────────────────────────────────────
    # Client FIN
    cli_fin_seq = cli_seq_after + len(payload)
    cli_fin = (IP(src=src, dst=dst, ttl=64) /
               TCP(sport=sport, dport=dport, flags="FA",
                   seq=cli_fin_seq, ack=srv_ack_val + len(confirm)))
    cli_fin.time = t; t += 0.001
    packets.append(cli_fin)

    # Server FIN-ACK
    srv_fin = (IP(src=dst, dst=src, ttl=64) /
               TCP(sport=dport, dport=sport, flags="FA",
                   seq=srv_ack_val + len(confirm), ack=cli_fin_seq + 1))
    srv_fin.time = t; t += 0.001
    packets.append(srv_fin)

    # Client final ACK
    cli_final_ack = (IP(src=src, dst=dst, ttl=64) /
                     TCP(sport=sport, dport=dport, flags="A",
                         seq=cli_fin_seq + 1, ack=srv_ack_val + len(confirm) + 1))
    cli_final_ack.time = t
    packets.append(cli_final_ack)

    out = pcap_path(1, "stream_capture.pcap")
    wrpcap(out, packets)
    print(f"    ✓ Wrote {len(packets)} packets → {out}")


# ==============================================================================
# CHALLENGE 2 — DNS Exfiltration
# Mission: The Green Goblin's DNS Trap
# Flag: FLAG{dns_1s_n0t_just_for_nam3s}
# ==============================================================================
def generate_challenge_2():
    """
    Encodes the flag with Base64, splits into DNS label chunks, and constructs
    DNS query/response packets for each chunk ordered by numeric prefix.
    Recovery: Extract subdomain labels → sort by index → Base64 decode.
    """
    print("[2/5] Generating The Green Goblin's DNS Trap (DNS exfil)...")

    attacker = "192.0.2.100"
    resolver  = "198.51.100.1"
    flag      = FLAGS[2]

    # Base64-encode the flag
    encoded = base64.b64encode(flag).decode()  # e.g. "RkxBR3tkbnNfMXNfbjB0X2p1c3RfZm9yX25hbTNzfQ=="

    # DNS labels must be ≤63 chars; use 16-char chunks for safety
    chunk_size = 16
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

    packets = []
    t = BASE_TIME + 10.0

    for idx, chunk in enumerate(chunks):
        # Label format: <index>-<chunk>.malicious.example.com
        label   = f"c{idx:02d}-{chunk}.malicious.example.com."
        txid    = 0x1000 + idx
        sport   = 54400 + idx

        # DNS Query
        qry = (IP(src=attacker, dst=resolver, ttl=64) /
               UDP(sport=sport, dport=53) /
               DNS(id=txid, rd=1,
                   qd=DNSQR(qname=label, qtype="A")))
        qry.time = t; t += 0.05
        packets.append(qry)

        # DNS Response (NXDOMAIN — domain doesn't exist, realistic for exfil)
        rsp = (IP(src=resolver, dst=attacker, ttl=64) /
               UDP(sport=53, dport=sport) /
               DNS(id=txid, qr=1, aa=0, rd=1, ra=1, rcode=3,
                   qd=DNSQR(qname=label, qtype="A")))
        rsp.time = t; t += 0.001
        packets.append(rsp)

    out = pcap_path(2, "dns_exfil.pcap")
    wrpcap(out, packets)
    print(f"    ✓ Encoded flag → {len(chunks)} DNS labels, {len(packets)} packets → {out}")
    print(f"      Base64: {encoded}")


# ==============================================================================
# CHALLENGE 3 — Ping of Secrets (ICMP hidden payload)
# Mission: Electro's Hidden Signal
# Flag: FLAG{p1ng_p4ylo4d_h1d3s_d4t4}
# ==============================================================================
def generate_challenge_3():
    """
    Sends ICMP echo requests with the flag embedded in the packet payload.
    Scapy auto-computes checksums for valid packets.
    Recovery: Wireshark → ICMP packet → Packet Bytes / Data field (ASCII visible)
    """
    print("[3/5] Generating Electro's Hidden Signal (ICMP hidden payload)...")

    src  = "192.0.2.15"
    dst  = "198.51.100.25"
    flag = FLAGS[3]

    packets = []
    t = BASE_TIME + 100.0

    for seq in range(5):
        # Echo Request with flag in payload
        req = (IP(src=src, dst=dst, ttl=64, id=0x1234 + seq) /
               ICMP(type=8, code=0, id=0xABCD, seq=seq) /
               Raw(load=flag + b" seq=" + str(seq).encode()))
        req.time = t; t += 1.0
        packets.append(req)

        # Echo Reply (server reflects the payload)
        rep = (IP(src=dst, dst=src, ttl=64, id=0x5678 + seq) /
               ICMP(type=0, code=0, id=0xABCD, seq=seq) /
               Raw(load=flag + b" seq=" + str(seq).encode()))
        rep.time = t - 0.001; t += 0.001
        packets.append(rep)

    out = pcap_path(3, "icmp_secret.pcap")
    wrpcap(out, packets)
    print(f"    ✓ Wrote {len(packets)} ICMP packets → {out}")


# ==============================================================================
# CHALLENGE 4 — Who Scanned Me? (TCP SYN scan simulation)
# Mission: Mysterio's Recon Network
# Flag: FLAG{p0rt_sc4nn3r_d3t3ct3d}
# ==============================================================================
def generate_challenge_4():
    """
    Simulates an offline TCP SYN port scan: attacker sends SYN probes against
    ports 1-100 (representative sample) + notable ports + 1337.
    Most ports respond RST (closed). Port 1337 responds SYN-ACK with a banner.
    NOTE: No real machines are scanned. All packets are constructed offline.
    Recovery:
      - Filter: tcp.flags.syn==1 && tcp.flags.ack==0 → identify scanner IP
      - Filter: tcp.port==1337 → Follow TCP Stream → read banner/flag
    """
    print("[4/5] Generating Mysterio's Recon Network (TCP SYN scan)...")

    attacker = "192.0.2.50"
    target   = "198.51.100.10"
    flag     = FLAGS[4]

    # Scan port range — use 1-100 as representative (full 1-1000 would be 1000+ packets)
    # then add a selection of known ports + 1337
    scan_ports = list(range(1, 101)) + [135, 139, 443, 445, 3389, 8080, 1337]
    # Remove duplicates and sort
    scan_ports = sorted(set(scan_ports))

    open_ports = {1337}   # Only port 1337 is "open"

    packets = []
    t = BASE_TIME + 200.0
    base_seq = 0x41424344

    for i, port in enumerate(scan_ports):
        seq = base_seq + i
        sport = 60000 + (i % 5000)

        # SYN probe
        syn = (IP(src=attacker, dst=target, ttl=45, id=0x4000 + i) /
               TCP(sport=sport, dport=port, flags="S",
                   seq=seq, window=1024,
                   options=[("MSS", 1460)]))
        syn.time = t; t += 0.001
        packets.append(syn)

        if port in open_ports:
            # SYN-ACK response (port is open)
            syn_ack = (IP(src=target, dst=attacker, ttl=64) /
                       TCP(sport=port, dport=sport, flags="SA",
                           seq=0xDEADBEEF, ack=seq + 1, window=65535))
            syn_ack.time = t; t += 0.001
            packets.append(syn_ack)

            # Attacker ACK (complete handshake for banner grab)
            ack = (IP(src=attacker, dst=target, ttl=45) /
                   TCP(sport=sport, dport=port, flags="A",
                       seq=seq + 1, ack=0xDEADBEEF + 1, window=1024))
            ack.time = t; t += 0.001
            packets.append(ack)

            # Target sends service banner with the flag
            banner = (b"220 SPIDER-VERSE-CTF Service v1.0\r\n"
                      b"Secret: " + flag + b"\r\n"
                      b"Welcome to the Mysterio Recon Network.\r\n")
            srv_banner = (IP(src=target, dst=attacker, ttl=64) /
                          TCP(sport=port, dport=sport, flags="PA",
                              seq=0xDEADBEEF + 1,
                              ack=seq + 1) /
                          Raw(load=banner))
            srv_banner.time = t; t += 0.002
            packets.append(srv_banner)

            # Attacker RST to close
            rst = (IP(src=attacker, dst=target, ttl=45) /
                   TCP(sport=sport, dport=port, flags="R",
                       seq=seq + 1))
            rst.time = t; t += 0.001
            packets.append(rst)

        else:
            # RST response (port closed — typical SYN scan result)
            rst = (IP(src=target, dst=attacker, ttl=64) /
                   TCP(sport=port, dport=sport, flags="RA",
                       seq=0, ack=seq + 1, window=0))
            rst.time = t; t += 0.0005
            packets.append(rst)

    out = pcap_path(4, "port_scan.pcap")
    wrpcap(out, packets)
    print(f"    ✓ Scanned {len(scan_ports)} ports (offline), {len(packets)} packets → {out}")
    print(f"      Open port: 1337 (banner contains flag)")


# ==============================================================================
# CHALLENGE 5 — HTTP Treasure Hunt (HTTP file carving)
# Mission: Doc Ock's Stolen File
# Flag: FLAG{http_f1l3_c4rv1ng_pr0}
# ==============================================================================
def generate_challenge_5():
    """
    Constructs a complete HTTP GET request/response TCP session.
    Client requests GET /secret_notes.txt HTTP/1.1
    Server responds 200 OK with the flag in the response body.
    Recovery: Wireshark → File > Export Objects > HTTP (or Follow TCP Stream)
    """
    print("[5/5] Generating Doc Ock's Stolen File (HTTP file carving)...")

    client = "192.0.2.200"
    server = "198.51.100.100"
    sport  = 54999
    dport  = 8080
    flag   = FLAGS[5]

    # HTTP request
    http_req  = (b"GET /secret_notes.txt HTTP/1.1\r\n"
                 b"Host: 198.51.100.100:8080\r\n"
                 b"User-Agent: Spider-Verse-CTF-Client/1.0\r\n"
                 b"Accept: */*\r\n"
                 b"Connection: close\r\n"
                 b"\r\n")

    # HTTP response body — the flag
    body      = (b"=== DOC OCK'S STOLEN NOTES ===\r\n"
                 b"Classification: TOP SECRET\r\n"
                 b"Author: Otto Octavius\r\n"
                 b"\r\n"
                 b"The secret you seek is below:\r\n"
                 b"\r\n" +
                 flag + b"\r\n"
                 b"\r\n"
                 b"-- End of File --\r\n")

    http_resp = (b"HTTP/1.1 200 OK\r\n"
                 b"Content-Type: text/plain\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                 b"Server: DocOck-Server/1.0\r\n"
                 b"Connection: close\r\n"
                 b"\r\n" + body)

    packets = []
    t = BASE_TIME + 300.0

    # TCP 3-way handshake
    cli_seq = 0x11223344
    srv_seq = 0xAABBCCDD

    syn = (IP(src=client, dst=server, ttl=64) /
           TCP(sport=sport, dport=dport, flags="S",
               seq=cli_seq, window=65535))
    syn.time = t; t += 0.001
    packets.append(syn)

    syn_ack = (IP(src=server, dst=client, ttl=64) /
               TCP(sport=dport, dport=sport, flags="SA",
                   seq=srv_seq, ack=cli_seq + 1, window=65535))
    syn_ack.time = t; t += 0.001
    packets.append(syn_ack)

    ack = (IP(src=client, dst=server, ttl=64) /
           TCP(sport=sport, dport=dport, flags="A",
               seq=cli_seq + 1, ack=srv_seq + 1, window=65535))
    ack.time = t; t += 0.001
    packets.append(ack)

    # HTTP GET request
    psh_req = (IP(src=client, dst=server, ttl=64) /
               TCP(sport=sport, dport=dport, flags="PA",
                   seq=cli_seq + 1, ack=srv_seq + 1) /
               Raw(load=http_req))
    psh_req.time = t; t += 0.005
    packets.append(psh_req)

    # Server ACK of request
    srv_ack = (IP(src=server, dst=client, ttl=64) /
               TCP(sport=dport, dport=sport, flags="A",
                   seq=srv_seq + 1, ack=cli_seq + 1 + len(http_req)))
    srv_ack.time = t; t += 0.001
    packets.append(srv_ack)

    # HTTP 200 OK response with flag
    psh_resp = (IP(src=server, dst=client, ttl=64) /
                TCP(sport=dport, dport=sport, flags="PA",
                    seq=srv_seq + 1, ack=cli_seq + 1 + len(http_req)) /
                Raw(load=http_resp))
    psh_resp.time = t; t += 0.002
    packets.append(psh_resp)

    # Client ACK of response
    cli_ack2 = (IP(src=client, dst=server, ttl=64) /
                TCP(sport=sport, dport=dport, flags="A",
                    seq=cli_seq + 1 + len(http_req),
                    ack=srv_seq + 1 + len(http_resp)))
    cli_ack2.time = t; t += 0.001
    packets.append(cli_ack2)

    # Server FIN (Connection: close)
    srv_fin = (IP(src=server, dst=client, ttl=64) /
               TCP(sport=dport, dport=sport, flags="FA",
                   seq=srv_seq + 1 + len(http_resp),
                   ack=cli_seq + 1 + len(http_req)))
    srv_fin.time = t; t += 0.001
    packets.append(srv_fin)

    # Client FIN-ACK
    cli_fin = (IP(src=client, dst=server, ttl=64) /
               TCP(sport=sport, dport=dport, flags="FA",
                   seq=cli_seq + 1 + len(http_req),
                   ack=srv_seq + 1 + len(http_resp) + 1))
    cli_fin.time = t; t += 0.001
    packets.append(cli_fin)

    # Server final ACK
    srv_final = (IP(src=server, dst=client, ttl=64) /
                 TCP(sport=dport, dport=sport, flags="A",
                     seq=srv_seq + 1 + len(http_resp) + 1,
                     ack=cli_seq + 1 + len(http_req) + 1))
    srv_final.time = t
    packets.append(srv_final)

    out = pcap_path(5, "http_transfer.pcap")
    wrpcap(out, packets)
    print(f"    ✓ Wrote {len(packets)} packets (HTTP GET /secret_notes.txt) → {out}")
    print(f"      Response body length: {len(body)} bytes")


# ==============================================================================
# Main Entry Point
# ==============================================================================
def main():
    print("=" * 65)
    print("  SPIDER-VERSE CTF — Network Forensics PCAP Generator")
    print("=" * 65)
    print()

    ensure_dirs()

    generate_challenge_1()
    print()
    generate_challenge_2()
    print()
    generate_challenge_3()
    print()
    generate_challenge_4()
    print()
    generate_challenge_5()

    print()
    print("=" * 65)
    print("  ✓ All 5 PCAP files generated successfully!")
    print()
    print("  Run  py -3 validate_project.py  to verify all captures.")
    print("=" * 65)


if __name__ == "__main__":
    main()
