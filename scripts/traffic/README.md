# Traffic Generation Scripts

These scripts generate basic traffic types (HTTP, DNS, SSH, iperf3, ping) for data collection and eBPF tests.

## Prereqs
- bash
- curl, dig, ssh, iperf3, ping
- Optional: python3 for a local HTTP server, iperf3 server

## Setup
chmod +x scripts/traffic/*.sh

## Examples
# local HTTP server
python3 -m http.server 8000

# HTTP
DURATION=20 TARGET_HTTP_URL=http://127.0.0.1:8000/ ./scripts/traffic/traffic_http.sh

# DNS
DURATION=20 DNS_NAME=example.com DNS_SERVER=127.0.0.1 ./scripts/traffic/traffic_dns.sh

# SSH
SSH_HOST=10.0.0.5 SSH_USER=student ./scripts/traffic/traffic_ssh.sh

# iperf3
IPERF_HOST=10.0.0.6 DURATION=15 ./scripts/traffic/traffic_iperf3.sh

# Ping
PING_HOST=127.0.0.1 DURATION=10 ./scripts/traffic/traffic_ping.sh

# Run all (sequential by default)
DURATION=15 PARALLEL=0 ./scripts/traffic/run_all.sh

## Notes
- Each script prints timestamps and runs for DURATION seconds.
- Use PARALLEL=1 with run_all.sh to mix flows.
- SSH uses BatchMode and will not prompt; set up key auth if needed.
