# Participant Guide — SPIDER-VERSE CTF

## Welcome, Spider-Investigator!

This guide will get you set up to compete in the SPIDER-VERSE CTF. No prior CTF experience required — just curiosity and Wireshark.

---

## Prerequisites

### Tools You Need

| Tool | Purpose | Download |
|---|---|---|
| Wireshark | Open and analyze PCAP files | [wireshark.org](https://www.wireshark.org/) |
| A web browser | Access CTFd platform | Any modern browser |

Optional (for advanced analysis):
- `tshark` — command-line Wireshark (included with Wireshark)
- Python 3 — for scripting extractions

---

## How to Compete

### Step 1 — Register
1. Browse to the CTFd platform (URL provided by organizer).
2. Click **Register** and create an account.
3. Join or create a team.

### Step 2 — Browse Challenges
1. Click **Challenges** in the navigation.
2. Read the mission briefing for each challenge.
3. Download the attached PCAP file.

### Step 3 — Investigate the PCAP
Open the PCAP file in Wireshark:
1. **File → Open** → select the `.pcap` file.
2. Use the filter bar to narrow down traffic.
3. Follow TCP/UDP streams for application-layer data.

### Step 4 — Find the Flag
All flags are in the format: `FLAG{...}`

### Step 5 — Submit
1. On the CTFd challenge page, enter the flag in the text box.
2. Click **Submit**.
3. A green banner = correct. Red = try again.

---

## Wireshark Quick Reference

### Essential Filters

| Filter | What it shows |
|---|---|
| `tcp` | All TCP traffic |
| `udp` | All UDP traffic |
| `dns` | All DNS traffic |
| `icmp` | All ICMP (ping) traffic |
| `http` | HTTP requests and responses |
| `tcp.port == 9001` | TCP traffic on port 9001 |
| `tcp.port == 1337` | TCP traffic on port 1337 |
| `tcp.port == 8080` | HTTP on port 8080 |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN-only packets (port scan probes) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | SYN-ACK (open port responses) |

### Follow TCP Stream (most important skill!)
1. Apply a filter to see TCP packets.
2. Right-click any packet in the list.
3. **Follow → TCP Stream**
4. The stream window shows the full conversation in order.
5. Use **Show data as: ASCII** to read plaintext data.

### Export HTTP Objects
For HTTP challenges:
- **File → Export Objects → HTTP**
- Find and save the transferred file.

---

## Challenge Hints

| # | Mission | Category | Tip |
|---|---|---|---|
| 1 | Peter Parker's Packet Trail | TCP Forensics | Follow the TCP Stream on port 9001 |
| 2 | Green Goblin's DNS Trap | DNS / Forensics | Look at subdomain labels, sort by index, Base64 decode |
| 3 | Electro's Hidden Signal | ICMP | Check the Data field of ICMP Echo Requests |
| 4 | Mysterio's Recon Network | Network Detection | Find the one port with a SYN-ACK, follow that stream |
| 5 | Doc Ock's Stolen File | HTTP / File Carving | File → Export Objects → HTTP (or Follow TCP Stream on port 8080) |

---

## What NOT to Do

- Do NOT scan any real machines. All challenges use offline PCAP files only.
- Do NOT share flags with other teams.
- Do NOT attack the CTFd platform itself.

---

## Getting Help

- Use the **Hints** button on each challenge (may cost points).
- Ask organizers via the event Discord/contact channel.

Good luck, and may your web be strong! 🕷️
