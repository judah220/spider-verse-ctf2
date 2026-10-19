# SPIDER-VERSE CTF — Architecture

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    SPIDER-VERSE CTF                          │
├──────────────────┬───────────────────┬───────────────────────┤
│  Landing Page    │  CTFd Platform    │  PCAP Challenges      │
│  (index.html)    │  (Docker)         │  (Python/Scapy)       │
│                  │                   │                       │
│  - Spider web    │  - User auth      │  - 5 PCAP files       │
│  - Countdown     │  - Challenges     │  - TCP stream         │
│  - Challenge     │  - Flag submit    │  - DNS exfil          │
│    cards         │  - Scoreboard     │  - ICMP payload       │
│  - CTFd links    │  - Admin panel    │  - Port scan          │
│                  │                   │  - HTTP carving       │
└──────────────────┴───────────────────┴───────────────────────┘
```

## Component Details

### Landing Page (`ctfd/theme/spider-verse/index.html`)
- Pure HTML/CSS/JS — no build step required
- Open directly in browser: `File → Open → index.html`
- Links to CTFd at `http://localhost:8000`
- Configurable event date via `EVENT_DATE` constant
- Configurable CTFd URL via `CTFD_BASE_URL` constant
- Animated spider-web canvas (particle nodes + edges)
- NYC skyline SVG (inline, no external images)
- Countdown timer (updates every second)
- Scroll-reveal animations
- Fully responsive (mobile-friendly)

### CTFd Platform (`docker-compose.yml`)
| Service | Image | Port |
|---|---|---|
| ctfd | ctfd/ctfd:latest | 8000 |
| db | mariadb:10.11 | internal |
| cache | redis:7-alpine | internal |

- All secrets in `.env` (never committed)
- PCAP uploads persist in Docker volume `uploads`

### PCAP Generator (`generate_pcaps.py`)
- Python 3 + Scapy 2.8+
- Fully offline (no live network access)
- Documentation IPs only (RFC 5737)
- Deterministic output (same result each run)

### Validation Script (`validate_project.py`)
- Reads back all 5 PCAPs with `rdpcap`
- Verifies protocols, IPs, ports, payloads
- Checks flag recoverability in each challenge
- Checks participant files don't leak flags

## Network Topology (Simulated / Offline)

```
192.0.2.0/24  (TEST-NET-1)    — Attacker / Client side
198.51.100.0/24 (TEST-NET-2)  — Server / Target side

Challenge 1:  192.0.2.10   → 198.51.100.20:9001  (TCP)
Challenge 2:  192.0.2.100  → 198.51.100.1:53     (DNS/UDP)
Challenge 3:  192.0.2.15   → 198.51.100.25       (ICMP)
Challenge 4:  192.0.2.50   → 198.51.100.10:1-1337 (TCP SYN scan)
Challenge 5:  192.0.2.200  → 198.51.100.100:8080 (HTTP)
```

## File Structure

```
SPIDER-VERSE-CTF/
├── docker-compose.yml          # CTFd + MariaDB + Redis
├── .env.example                # Safe placeholder config
├── .gitignore
├── requirements.txt            # Python deps (scapy)
├── generate_pcaps.py           # PCAP generator
├── validate_project.py         # Automated validation
├── README.md                   # Main documentation
├── challenges/
│   ├── 01_follow_the_stream/
│   │   ├── stream_capture.pcap  # TCP stream (port 9001)
│   │   ├── challenge.txt        # Participant description
│   │   └── solution.txt         # Organizer solution (private)
│   ├── 02_dns_exfiltration/
│   │   ├── dns_exfil.pcap       # DNS-based exfil
│   │   ├── challenge.txt
│   │   └── solution.txt
│   ├── 03_ping_of_secrets/
│   │   ├── icmp_secret.pcap     # ICMP payload
│   │   ├── challenge.txt
│   │   └── solution.txt
│   ├── 04_who_scanned_me/
│   │   ├── port_scan.pcap       # TCP SYN scan + port 1337
│   │   ├── challenge.txt
│   │   └── solution.txt
│   └── 05_http_treasure_hunt/
│       ├── http_transfer.pcap   # HTTP file transfer
│       ├── challenge.txt
│       └── solution.txt
├── ctfd/
│   ├── challenges_import.json   # CTFd challenge definitions
│   ├── setup_challenges.py      # CTFd API setup script
│   └── theme/
│       └── spider-verse/
│           ├── index.html       # Standalone landing page
│           └── theme.json       # Theme metadata
└── docs/
    ├── architecture.md          # This file
    ├── organizer-guide.md
    └── participant-guide.md
```
