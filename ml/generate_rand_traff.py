import pandas as pd
import numpy as np

np.random.seed(42)
n = 300

def gen_http(n):
    return pd.DataFrame({
        'protocol': [6]*n,
        'src_port': np.random.choice([80, 443, 8080], n),
        'dst_port': np.random.randint(49152, 65535, n),
        'pkt_count': np.random.randint(5, 30, n),
        'byte_count': np.random.randint(1000, 50000, n),
        'duration_ms': np.random.randint(50, 500, n),
        'avg_ipt_ms': np.random.uniform(5, 50, n),
        'label': 'HTTP'
    })

def gen_icmp(n):
    return pd.DataFrame({
        'protocol': [1]*n,
        'src_port': [0]*n,
        'dst_port': [0]*n,
        'pkt_count': np.random.randint(1, 6, n),
        'byte_count': np.random.randint(64, 500, n),
        'duration_ms': np.random.randint(5, 100, n),
        'avg_ipt_ms': np.random.uniform(10, 100, n),
        'label': 'ICMP'
    })

def gen_dns(n):
    return pd.DataFrame({
        'protocol': [17]*n,
        'src_port': [53]*n,
        'dst_port': np.random.randint(49152, 65535, n),
        'pkt_count': np.random.randint(1, 4, n),
        'byte_count': np.random.randint(50, 300, n),
        'duration_ms': np.random.randint(1, 30, n),
        'avg_ipt_ms': np.random.uniform(1, 10, n),
        'label': 'DNS'
    })

df = pd.concat([gen_http(n), gen_icmp(n), gen_dns(n)]).sample(frac=1).reset_index(drop=True)
df.to_csv('ml/data/synthetic_flows.csv', index=False)
print(f"Saved {len(df)} rows to ml/data/synthetic_flows.csv")
