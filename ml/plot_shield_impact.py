#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np
import os

def plot_shield_impact():
    labels = ['Passive Mode\n(Detection Only)', 'Active Mode\n(ML Shield)']
    allowed_traffic = [100, 5]  # Simulated % of malicious traffic allowed
    blocked_traffic = [0, 95]    # Simulated % of malicious traffic blocked
    
    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, allowed_traffic, width, label='Allowed (Threats)', color='#e74c3c')
    rects2 = ax.bar(x + width/2, blocked_traffic, width, label='Blocked (Shield)', color='#2ecc71')

    ax.set_ylabel('Traffic Percentage (%)')
    ax.set_title('Impact of Adaptive ML Shield on Network Threats', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.set_ylim(0, 110)

    # Add labels on top of bars
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate('{}%'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)

    plt.tight_layout()
    os.makedirs("ml/results", exist_ok=True)
    plt.savefig("ml/results/shield_impact.png", dpi=150)
    print("Saved: ml/results/shield_impact.png")

if __name__ == "__main__":
    plot_shield_impact()
