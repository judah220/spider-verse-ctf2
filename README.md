# 🕷️ SPIDER-VERSE CTF — Web of Cyber Secrets

> **Hack the System. Unmask the Threat. Save the Multiverse.**

A complete cybersecurity Capture The Flag platform with five network forensics challenges. Combine a cinematic Spider-Man-inspired landing page with the official CTFd platform and real, downloadable PCAP files.

---

## 📋 Quick Start

### Prerequisites

| Software | Purpose | Install |
|---|---|---|
| Python 3.8+ | PCAP generator | [python.org](https://www.python.org/) |
| Scapy | Packet construction | `py -3 -m pip install scapy` |
| Docker Desktop | CTFd deployment | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| Wireshark | PCAP analysis | [wireshark.org](https://www.wireshark.org/) |

### 3-Command Quick Start

```powershell
# 1. Install dependency
py -3 -m pip install scapy

# 2. Generate PCAP files
py -3 generate_pcaps.py

# 3. Validate all captures
py -3 validate_project.py
```

---

## Project Structure

```
SPIDER-VERSE-CTF/
├── docker-compose.yml              # CTFd + MariaDB + Redis
├── .env.example                    # Config template (copy to .env)
├── .gitignore
├── requirements.txt                # Python deps
├── generate_pcaps.py               # 🔬 PCAP generator (5 challenges)
├── validate_project.py             # ✅ Automated validation
├── README.md
├── challenges/
│   ├── 01_follow_the_stream/
│   │   ├── stream_capture.pcap     # TCP stream on port 9001
│   │   ├── challenge.txt           # Participant description
│   │   └── solution.txt            # ⚠ Organizer only
│   ├── 02_dns_exfiltration/
│   │   ├── dns_exfil.pcap          # DNS exfil with Base64 encoding
│   │   ├── challenge.txt
│   │   └── solution.txt
│   ├── 03_ping_of_secrets/
│   │   ├── icmp_secret.pcap        # ICMP payload
│   │   ├── challenge.txt
│   │   └── solution.txt
│   ├── 04_who_scanned_me/
│   │   ├── port_scan.pcap          # TCP SYN scan + port 1337 banner
│   │   ├── challenge.txt
│   │   └── solution.txt
│   └── 05_http_treasure_hunt/
│       ├── http_transfer.pcap      # HTTP GET /secret_notes.txt
│       ├── challenge.txt
│       └── solution.txt
├── ctfd/
│   ├── challenges_import.json      # Challenge definitions
│   ├── setup_challenges.py         # CTFd API setup script
│   └── theme/spider-verse/
│       ├── index.html              # 🕷 Spider-Verse landing page
│       └── theme.json
└── docs/
    ├── architecture.md
    ├── organizer-guide.md          # Full setup documentation
    └── participant-guide.md
```

---

## Phase 1 — Generate PCAP Files

```powershell
# Windows
py -3 -m pip install scapy
py -3 generate_pcaps.py

# Linux / macOS / Kali
python3 -m pip install scapy
python3 generate_pcaps.py
```

This creates all 5 PCAP files. No network access, no root required.

---

## Phase 2 — Validate Captures

```powershell
py -3 validate_project.py
```

Expected: `5 challenges × multiple checks = all PASS` ✅

---

## Phase 3 — View the Landing Page

Open in any browser — no web server needed:
```
SPIDER-VERSE-CTF/ctfd/theme/spider-verse/index.html
```

To configure:
- Edit `EVENT_DATE` near the bottom of `index.html` (for countdown timer)
- Edit `CTFD_BASE_URL` to point to your CTFd deployment

---

## Phase 4 — Deploy CTFd

### Windows (Docker Desktop)
```powershell
# 1. Copy and edit config
copy .env.example .env
notepad .env

# 2. Start with Docker Desktop open
docker compose up -d

# 3. Browse to CTFd
start http://localhost:8000
```

### Linux / Ubuntu / Kali
```bash
cp .env.example .env
nano .env          # fill in passwords

docker compose up -d
# or: docker-compose up -d (older versions)
```

### Stop/Restart
```powershell
docker compose down           # stop
docker compose down -v        # stop + wipe all data
docker compose restart ctfd   # restart app only
```

---

## Phase 5 — Configure CTFd

1. Browse to **http://localhost:8000** — complete the setup wizard.
2. Get an API token: **Admin → Config → Settings → Access Tokens**
3. Run the challenge setup script:
   ```powershell
   py -3 ctfd\setup_challenges.py --url http://localhost:8000 --token YOUR_TOKEN
   ```
4. In the Admin Panel, for each challenge, upload the PCAP under **Files**.

For full step-by-step instructions see [`docs/organizer-guide.md`](docs/organizer-guide.md).

---

## The 5 Challenges

| # | Mission | Category | Difficulty | Points | Tool |
|---|---|---|---|---|---|
| 1 | Peter Parker's Packet Trail | Network Forensics | Easy | 100 | Follow TCP Stream |
| 2 | The Green Goblin's DNS Trap | DNS / Forensics | Easy–Med | 150 | DNS query labels + Base64 |
| 3 | Electro's Hidden Signal | ICMP / Forensics | Easy | 100 | ICMP payload bytes |
| 4 | Mysterio's Recon Network | Network Detection | Medium | 200 | SYN scan analysis + port 1337 |
| 5 | Doc Ock's Stolen File | HTTP / File Carving | Medium | 200 | Export Objects / Follow Stream |
| | **Total** | | | **750** | |

---

## Wireshark Filters (Quick Reference)

```
# General
tcp                                     All TCP
udp                                     All UDP
dns                                     All DNS
icmp                                    All ICMP
http                                    All HTTP

# Challenge-specific
tcp.port == 9001                        Challenge 1 (TCP stream)
dns && dns.qry.name contains "malicious" Challenge 2 (DNS exfil)
icmp.type == 8                          Challenge 3 (ICMP requests)
tcp.flags.syn==1 && tcp.flags.ack==0   Challenge 4 (SYN probes)
tcp.flags.syn==1 && tcp.flags.ack==1   Challenge 4 (open port)
tcp.port == 1337                        Challenge 4 (service banner)
tcp.port == 8080                        Challenge 5 (HTTP)
http.request                            HTTP GET requests
http.response                           HTTP responses
```

---

## Distributing Files to Participants

**Safe to share:**
- `challenges/*/stream_capture.pcap` (and other *.pcap)
- `challenges/*/challenge.txt`
- `docs/participant-guide.md`

**Keep organizer-only (NEVER share):**
- `challenges/*/solution.txt`
- `.env` file and credentials
- The flags themselves (stored only in CTFd admin)

---

## Testing Flag Submission

```
# Correct flag submission test (Challenge 1):
1. Register a test account at http://localhost:8000/register
2. Open Challenge 1
3. Enter: FLAG{n3tw0rk_str3am_1s_fun}
4. Confirm: green success banner + points on scoreboard

# Incorrect submission test:
1. Enter: FLAG{wrong_flag}
2. Confirm: red error, no points
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `py` command not found | Use `python3` on Linux/macOS |
| `scapy` import error | `py -3 -m pip install scapy` |
| Docker Desktop not running | Open Docker Desktop app, wait for "Running" status |
| Port 8000 in use | Change `"8000:8000"` to `"8001:8000"` in docker-compose.yml |
| DB connection error | `docker compose restart ctfd` after 30s |
| PCAP missing | Run `py -3 generate_pcaps.py` |
| API token invalid | Generate new token in CTFd Admin → Settings |

---

## Architecture

```
Landing Page (index.html) ──→ CTFd (http://localhost:8000)
                                      │
                      ┌───────────────┼───────────────┐
                      ▼               ▼               ▼
                  MariaDB         Redis Cache      PCAP Files
                 (challenge     (sessions &       (Docker
                   data)          scoring)         volume)
```

See [`docs/architecture.md`](docs/architecture.md) for full details.

---

## ⚠️ Production Warning

The included `docker-compose.yml` is for **local / development** use only. For a public event:
- Add HTTPS via a reverse proxy (nginx + certbot)
- Use strong, unique secrets in `.env`
- Set CTFd visibility to private until event start
- Review [CTFd's official deployment docs](https://docs.ctfd.io/docs/deployment/installation)

---

## Credits

- Platform: [CTFd](https://ctfd.io) (official image)
- PCAP Generation: [Scapy](https://scapy.net)
- Design: Original Spider-Verse inspired theme (no copyrighted assets used)
- IP Ranges: RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24)

---

*"With Great Power Comes Great Responsibility."*
