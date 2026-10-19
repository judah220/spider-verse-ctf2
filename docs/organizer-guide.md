# Organizer Guide — SPIDER-VERSE CTF

> ⚠️ **CONFIDENTIAL** — This document contains organizer-only information including setup procedures. Do not share with participants.

---

## Quick Start (TL;DR)

```powershell
# 1. Install Python dependency
py -3 -m pip install scapy

# 2. Generate all PCAP files
cd SPIDER-VERSE-CTF
py -3 generate_pcaps.py

# 3. Validate all captures
py -3 validate_project.py

# 4. Start CTFd (requires Docker Desktop)
copy .env.example .env    # then edit .env with real values
docker compose up -d

# 5. Open CTFd at http://localhost:8000
# 6. Create admin account via setup wizard
# 7. Setup challenges via API script (see below)
```

---

## Phase 1 — Environment Setup

### Requirements

| Software | Version | Purpose |
|---|---|---|
| Python | 3.8+ | PCAP generator |
| Scapy | 2.5+ | Packet construction |
| Docker Desktop | Latest | CTFd deployment |
| Wireshark | Latest | PCAP verification |

### Install Python Dependencies

```powershell
# Windows
py -3 -m pip install -r requirements.txt

# Linux/macOS
python3 -m pip install -r requirements.txt
```

---

## Phase 2 — Generate PCAP Files

```powershell
py -3 generate_pcaps.py
```

Expected output:
```
[1/5] Generating Peter Parker's Packet Trail (TCP stream)...
    ✓ Wrote 11 packets → challenges/01_follow_the_stream/stream_capture.pcap

[2/5] Generating The Green Goblin's DNS Trap (DNS exfil)...
    ✓ Encoded flag → N DNS labels, N packets → challenges/02_dns_exfiltration/dns_exfil.pcap

[3/5] Generating Electro's Hidden Signal (ICMP hidden payload)...
    ✓ Wrote 10 ICMP packets → challenges/03_ping_of_secrets/icmp_secret.pcap

[4/5] Generating Mysterio's Recon Network (TCP SYN scan)...
    ✓ Scanned N ports (offline), N packets → challenges/04_who_scanned_me/port_scan.pcap

[5/5] Generating Doc Ock's Stolen File (HTTP file carving)...
    ✓ Wrote 10 packets (HTTP GET /secret_notes.txt) → challenges/05_http_treasure_hunt/http_transfer.pcap

✓ All 5 PCAP files generated successfully!
```

---

## Phase 3 — Validate Captures

```powershell
py -3 validate_project.py
```

All checks should show `[PASS]`. If any fail, re-run `generate_pcaps.py` first.

---

## Phase 4 — Configure Environment Variables

```powershell
copy .env.example .env
notepad .env
```

Edit these values:
```env
SECRET_KEY=your-long-random-secret-here
MYSQL_ROOT_PASSWORD=strong-root-password
MYSQL_PASSWORD=strong-ctfd-password
CTFD_ADMIN_EMAIL=your@email.com
CTFD_ADMIN_PASSWORD=strong-admin-password

# Update the event date for your countdown
EVENT_DATE=2026-11-01T09:00:00
```

> ⚠️ **Never commit `.env` to version control.**

---

## Phase 5 — Launch CTFd with Docker

### Windows (Docker Desktop)

1. Open **Docker Desktop** from the Start menu. Wait until it shows "Running."
2. Open PowerShell in the `SPIDER-VERSE-CTF` directory.
3. Run:
   ```powershell
   docker compose up -d
   ```
4. Wait ~30 seconds for all services to start.
5. Browse to **http://localhost:8000**

### Linux / WSL / Kali / Ubuntu

```bash
docker compose up -d
# or for older installations:
docker-compose up -d
```

### Stop CTFd

```powershell
docker compose down
```

### View Logs

```powershell
docker compose logs -f ctfd
```

---

## Phase 6 — First-Time CTFd Setup

1. Browse to **http://localhost:8000**
2. Complete the setup wizard:
   - **CTF Name:** SPIDER-VERSE CTF
   - **Admin Email:** (your organizer email)
   - **Admin Password:** (strong password)
   - **Mode:** Users or Teams
   - **Visibility:** Private (until event starts)
3. Click **Finish**

---

## Phase 7 — Import Challenges

### Method A — API Script (Automated)

1. Get an API token: **Admin Panel → Config → Settings → Access Tokens → Generate**
2. Run the setup script:
   ```powershell
   py -3 ctfd\setup_challenges.py --url http://localhost:8000 --token YOUR_API_TOKEN
   ```
3. This creates all 5 challenges with descriptions, hints, and flags.

### Method B — Manual Admin Panel

1. Go to **Admin → Challenges → + New Challenge**
2. For each challenge:
   - Copy name/description from `ctfd/challenges_import.json`
   - Set category, points, and visibility
   - Under **Flags**, add the exact flag string (static type)
   - Under **Files**, upload the corresponding PCAP file
   - Save

---

## Phase 8 — Attach PCAP Files

In CTFd Admin → Challenges → (each challenge) → **Files** tab:
- Click **Choose File** → navigate to the PCAP
- Click **Upload**
- Participants will see a download link on the challenge page

| Challenge | PCAP File |
|---|---|
| #1 Peter Parker's Packet Trail | `challenges/01_follow_the_stream/stream_capture.pcap` |
| #2 Green Goblin's DNS Trap | `challenges/02_dns_exfiltration/dns_exfil.pcap` |
| #3 Electro's Hidden Signal | `challenges/03_ping_of_secrets/icmp_secret.pcap` |
| #4 Mysterio's Recon Network | `challenges/04_who_scanned_me/port_scan.pcap` |
| #5 Doc Ock's Stolen File | `challenges/05_http_treasure_hunt/http_transfer.pcap` |

---

## Phase 9 — Configure the Landing Page

Edit `ctfd/theme/spider-verse/index.html`:

```javascript
// Line ~625 — update these two constants:
const EVENT_DATE    = '2026-11-01T09:00:00';   // your event date
const CTFD_BASE_URL = 'http://localhost:8000';  // your public CTFd URL
```

Open `index.html` in any browser to verify the landing page works.

---

## Phase 10 — Test Submissions

### Test Correct Flag Submission

1. Register a test participant account.
2. Open any challenge.
3. Submit the correct flag (from `solution.txt`).
4. Verify: ✅ green confirmation, points added on scoreboard.

### Test Incorrect Flag Submission

1. Submit a wrong flag string.
2. Verify: ❌ red error message, no points awarded.

### Test Registration and Scoreboard

1. Register 2-3 test accounts.
2. Submit flags from multiple accounts.
3. Check **Scoreboard** — confirm correct ranking order.

---

## Sharing PCAP Files Safely

> **Share ONLY the PCAP files with participants — never share `solution.txt` files.**

### Safe to share:
- `*.pcap` files (the challenge captures)
- `challenge.txt` files (participant descriptions)
- `docs/participant-guide.md`

### Keep private (organizer only):
- `solution.txt` files
- `.env` file
- `ctfd/setup_challenges.py` (contains flag references)
- CTFd admin credentials

### Distribution options:
1. **CTFd file attachments** (recommended) — participants download from the challenge page.
2. **ZIP download** — bundle only the `*.pcap` and `challenge.txt` files for each challenge.

---

## Flags Reference (ORGANIZER ONLY)

| # | Challenge | Flag |
|---|---|---|
| 1 | Peter Parker's Packet Trail | `FLAG{n3tw0rk_str3am_1s_fun}` |
| 2 | Green Goblin's DNS Trap | `FLAG{dns_1s_n0t_just_for_nam3s}` |
| 3 | Electro's Hidden Signal | `FLAG{p1ng_p4ylo4d_h1d3s_d4t4}` |
| 4 | Mysterio's Recon Network | `FLAG{p0rt_sc4nn3r_d3t3ct3d}` |
| 5 | Doc Ock's Stolen File | `FLAG{http_f1l3_c4rv1ng_pr0}` |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `docker: command not found` | Open Docker Desktop app first, or install Docker |
| CTFd not loading at :8000 | Check `docker compose logs ctfd` |
| Database connection error | Wait 30s for MariaDB healthcheck, or `docker compose restart ctfd` |
| PCAP file not found by validator | Run `py -3 generate_pcaps.py` first |
| Scapy not installed | `py -3 -m pip install scapy` |
| API token error | Generate token in CTFd Admin → Config → Settings |

### Cleanup

```powershell
# Stop and remove containers, networks
docker compose down

# Remove all data (volumes) — WARNING: deletes all CTFd data
docker compose down -v
```

---

## Production Warning

> ⚠️ The default `docker-compose.yml` is for **local development only**. For a public event:
> - Use HTTPS (add nginx + certbot or a reverse proxy)
> - Use strong, unique passwords
> - Restrict admin panel access
> - Set CTFd visibility controls appropriately
> - Review CTFd's official deployment documentation
