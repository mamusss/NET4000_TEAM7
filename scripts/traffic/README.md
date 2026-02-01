# Traffic Generation Scripts

These scripts generate basic traffic types (HTTP, DNS, SSH, iperf3, ping) for data collection and eBPF tests.

## Prerequisites
- bash
- curl, dig, ssh, iperf3, ping
- Optional: python3 for a local HTTP server

If tools are missing (Debian/Ubuntu):
```bash
sudo apt install -y dnsutils iperf3
```

## Setup
```bash
chmod +x scripts/traffic/*.sh
```

## Quick start (loopback)
```bash
# Start a local HTTP server
python3 -m http.server 8000 --bind 127.0.0.1 &

# Generate HTTP traffic
DURATION=15 TARGET_HTTP_URL=http://127.0.0.1:8000/ ./scripts/traffic/traffic_http.sh

# Stop the server
kill %1
```

## Real interface traffic (wlo1/tailscale0)
```bash
# Find your IP
ip -br addr

# Start a server that listens on all interfaces
python3 -m http.server 8000 --bind 0.0.0.0

# From another machine on the same network:
# curl http://<VM_IP>:8000/
# ping <VM_IP>
```

## Individual flows
```bash
# HTTP
DURATION=20 TARGET_HTTP_URL=http://127.0.0.1:8000/ ./scripts/traffic/traffic_http.sh

# DNS
DURATION=20 DNS_NAME=example.com DNS_SERVER=127.0.0.1 ./scripts/traffic/traffic_dns.sh

# SSH (requires key auth)
SSH_HOST=10.0.0.5 SSH_USER=student ./scripts/traffic/traffic_ssh.sh

# iperf3 (server must be running on the target)
# On target: iperf3 -s
IPERF_HOST=10.0.0.6 DURATION=15 ./scripts/traffic/traffic_iperf3.sh

# Ping
PING_HOST=127.0.0.1 DURATION=10 ./scripts/traffic/traffic_ping.sh

# Run all (sequential by default)
DURATION=15 PARALLEL=0 ./scripts/traffic/run_all.sh
```

## Verify traffic (optional)
```bash
# Replace <iface> with lo, wlo1, or tailscale0
sudo tcpdump -ni <iface> port 8000
sudo tcpdump -ni <iface> port 53
sudo tcpdump -ni <iface> icmp
```

## Notes
- Each script prints timestamps and runs for DURATION seconds.
- Use PARALLEL=1 with run_all.sh to mix flows.
- SSH uses BatchMode and will not prompt; set up key auth if needed.