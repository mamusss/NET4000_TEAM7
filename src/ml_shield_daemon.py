#!/usr/bin/env python3
"""
ml_shield_daemon.py
The intelligent core: Live inference + Adaptive Kernel Mitigation.
"""

import sys, os, time, struct, socket, subprocess, json
import joblib
import pandas as pd
import numpy as np

# Load model and encoders
MODEL_PATH = "ml/models/rf_model.pkl"
LE_PATH = "ml/models/label_encoder.pkl"
FEAT_PATH = "ml/models/features.pkl"

def log(msg):
    print(f"[ML-SHIELD] {msg}")

def run_bpf_cmd(cmd):
    try:
        return subprocess.check_output(cmd)
    except: return None

def get_map_id(map_name):
    try:
        res = run_bpf_cmd(["bpftool", "map", "show", "name", map_name, "-j"])
        if res:
            info = json.loads(res)
            if isinstance(info, list) and len(info) > 0:
                return info[0]["id"]
            elif isinstance(info, dict):
                return info["id"]
    except: pass
    return None

def read_bpf_map(map_name):
    map_id = get_map_id(map_name)
    if not map_id: return []
    try:
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", str(map_id), "-j"])
        return json.loads(dump)
    except: return []

def update_bpf_map(map_name, key_bytes, val_bytes):
    map_id = get_map_id(map_name)
    if not map_id: 
        log(f"Warning: Map {map_name} not found")
        return False
    cmd = ["bpftool", "map", "update", "id", str(map_id), "key"] + [f"0x{b:02x}" for b in key_bytes] + ["value"] + [f"0x{b:02x}" for b in val_bytes]
    return run_bpf_cmd(cmd) is not None

def ip_to_str(ver, ip_bytes):
    try:
        if ver == 4:
            return socket.inet_ntop(socket.AF_INET, bytes(ip_bytes[:4]))
        return socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
    except: return "???"

class MLShield:
    def __init__(self):
        if not all(os.path.exists(p) for p in [MODEL_PATH, LE_PATH, FEAT_PATH]):
            log("Error: Model files not found. Run 'make train' first.")
            sys.exit(1)
        
        self.model = joblib.load(MODEL_PATH)
        self.le = joblib.load(LE_PATH)
        self.features = joblib.load(FEAT_PATH)
        log("ML Model loaded successfully.")
        
        # Initial config: Active Mitigation = ON, Threshold = 1000
        update_bpf_map("config_map", [0,0,0,0], [1,0,0,0])
        update_bpf_map("config_map", [1,0,0,0], [0xe8,0x03,0,0]) # 1000
        log("Kernel Mitigation Active (Threshold: 1000)")

    def process_flows(self):
        entries = read_bpf_map("flow_map")
        if not entries: return

        rows = []
        ips = []
        for e in entries:
            try:
                # bpftool -j can return key/value as integers or hex strings depending on version
                def to_bytes(raw, length):
                    if isinstance(raw, int):
                        return struct.pack("<Q", raw)[:length] if length <= 8 else struct.pack("<QQ", raw, 0)[:length]
                    if isinstance(raw, list):
                        return bytes([int(x, 16) if isinstance(x, str) else x for x in raw])
                    return bytes(raw)

                # key is 38 bytes, value is 64 bytes
                k = to_bytes(e['key'], 38)
                v = to_bytes(e['value'], 64)
                
                if len(k) < 38: continue
                ver = k[33]
            except Exception as ex:
                log(f"Error parsing entry: {ex}")
                continue

            if ver != 4: continue # Simple IPv4 for ML features for now
            
            src_ip = ip_to_str(ver, k[0:16])
            ips.append(src_ip)
            
            pkts = struct.unpack("<Q", v[0:8])[0]
            bytes_count = struct.unpack("<Q", v[8:16])[0]
            first_ts = struct.unpack("<Q", v[16:24])[0]
            last_ts = struct.unpack("<Q", v[24:32])[0]
            ipt_sum = struct.unpack("<Q", v[32:40])[0]
            min_ipt = struct.unpack("<Q", v[40:48])[0]
            max_ipt = struct.unpack("<Q", v[48:56])[0]
            
            duration_ms = (last_ts - first_ts) / 1e6
            avg_ipt_ms = (ipt_sum / (pkts - 1)) / 1e6 if pkts > 1 else 0
            
            rows.append({
                'protocol': k[32],
                'version': ver,
                'src_port': struct.unpack(">H", k[34:36])[0],
                'dst_port': struct.unpack(">H", k[36:38])[0],
                'pkt_count': pkts,
                'byte_count': bytes_count,
                'duration_ms': duration_ms,
                'avg_ipt_ms': avg_ipt_ms,
                'min_ipt_ms': min_ipt / 1e6,
                'max_ipt_ms': max_ipt / 1e6,
                'tcp_flags': v[56]
            })

        if not rows: return
        
        df = pd.DataFrame(rows)
        # Ensure all required features are present
        for f in self.features:
            if f not in df.columns: df[f] = 0
        
        X = df[self.features]
        preds = self.model.predict(X)
        labels = self.le.inverse_transform(preds)

        # Active blocking logic based on ML classification
        for i, label in enumerate(labels):
            if label in ["QUIC", "IPERF"] and rows[i]['pkt_count'] > 500:
                # Example: Block high-volume unknown/stress traffic identified by ML
                ip_to_block = ips[i]
                log(f"ML ALERT: Detected potential {label} threat from {ip_to_block}. Blocking...")
                ip_bytes = list(socket.inet_aton(ip_to_block))
                now = int(time.time() * 1e9)
                update_bpf_map("block_list_map", ip_bytes, struct.pack("<Q", now))

    def run(self):
        try:
            while True:
                self.process_flows()
                time.sleep(2)
        except KeyboardInterrupt:
            log("Shutting down...")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root")
        sys.exit(1)
    
    shield = MLShield()
    shield.run()
