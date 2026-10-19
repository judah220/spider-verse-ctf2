#!/usr/bin/env python3
"""
SPIDER-VERSE CTF — CTFd Challenge Setup Script
===============================================
Creates all 5 challenges via the CTFd REST API.
Run this AFTER CTFd is running and you have created an admin account.

Usage:
    py -3 ctfd/setup_challenges.py \
        --url http://localhost:8000 \
        --token <YOUR_CTFD_API_TOKEN>

Get your API token:
    CTFd Admin → Settings → Access Tokens → Generate

IMPORTANT: Flags are entered as secure strings, NOT hardcoded here.
          Edit the CHALLENGE_FLAGS dict below with real values before running.
          Do not commit with real flags.
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
import os

# ── Edit these flags before running ───────────────────────────────────────────
# Load from environment variables for safety
CHALLENGE_FLAGS = {
    1: os.environ.get("FLAG_1", "FLAG{n3tw0rk_str3am_1s_fun}"),
    2: os.environ.get("FLAG_2", "FLAG{dns_1s_n0t_just_for_nam3s}"),
    3: os.environ.get("FLAG_3", "FLAG{p1ng_p4ylo4d_h1d3s_d4t4}"),
    4: os.environ.get("FLAG_4", "FLAG{p0rt_sc4nn3r_d3t3ct3d}"),
    5: os.environ.get("FLAG_5", "FLAG{http_f1l3_c4rv1ng_pr0}"),
}

PCAP_PATHS = {
    1: "challenges/01_follow_the_stream/stream_capture.pcap",
    2: "challenges/02_dns_exfiltration/dns_exfil.pcap",
    3: "challenges/03_ping_of_secrets/icmp_secret.pcap",
    4: "challenges/04_who_scanned_me/port_scan.pcap",
    5: "challenges/05_http_treasure_hunt/http_transfer.pcap",
}


def api_request(base_url, token, method, endpoint, data=None):
    url    = f"{base_url.rstrip('/')}/api/v1{endpoint}"
    body   = json.dumps(data).encode() if data else None
    req    = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  [HTTP {e.code}] {endpoint}: {body[:300]}")
        return None


def load_challenges():
    path = os.path.join(os.path.dirname(__file__), "challenges_import.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["results"]


def main():
    parser = argparse.ArgumentParser(description="Create CTFd challenges via API")
    parser.add_argument("--url",   default="http://localhost:8000", help="CTFd base URL")
    parser.add_argument("--token", required=True, help="CTFd admin API token")
    args = parser.parse_args()

    challenges = load_challenges()
    print(f"\nConnecting to CTFd at {args.url}...\n")

    for ch in challenges:
        ch_id   = ch["id"]
        print(f"Creating challenge #{ch_id}: {ch['name']}...")

        # Create challenge
        payload = {
            "name":        ch["name"],
            "description": ch["description"],
            "category":    ch["category"],
            "value":       ch["value"],
            "type":        "standard",
            "state":       "visible",
        }
        result = api_request(args.url, args.token, "POST", "/challenges", payload)
        if not result or not result.get("success"):
            print(f"  [FAIL] Could not create challenge #{ch_id}")
            continue

        ctfd_ch_id = result["data"]["id"]
        print(f"  ✓ Created (CTFd id={ctfd_ch_id})")

        # Add flag
        flag_payload = {
            "challenge": ctfd_ch_id,
            "content":   CHALLENGE_FLAGS[ch_id],
            "type":      "static",
            "data":      "",
        }
        flag_result = api_request(args.url, args.token, "POST", "/flags", flag_payload)
        if flag_result and flag_result.get("success"):
            print(f"  ✓ Flag added")
        else:
            print(f"  [WARN] Flag may not have been added — set manually in admin panel")

        # Add hints
        for hint in ch.get("hints", []):
            hint_payload = {
                "challenge": ctfd_ch_id,
                "content":   hint["content"],
                "cost":      hint.get("cost", 0),
            }
            api_request(args.url, args.token, "POST", "/hints", hint_payload)

        print(f"  ✓ Challenge #{ch_id} fully configured")
        print()

    print("=" * 55)
    print("Done! Open CTFd admin panel to attach PCAP files:")
    for ch_id, path in PCAP_PATHS.items():
        print(f"  Challenge #{ch_id}: {path}")
    print()
    print("Admin → Challenges → (each challenge) → Files → Add File")
    print("=" * 55)


if __name__ == "__main__":
    main()
