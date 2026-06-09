import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Load data from exported files
df_types = pd.read_csv('/tmp/types.csv', sep='\t')
df_types.columns = ['Type', 'Count']

df_cats = pd.read_csv('/tmp/categories.csv', sep='\t')
df_cats.columns = ['Category', 'Count']

df_feeds = pd.read_csv('/tmp/feeds.csv', sep='\t')
df_feeds.columns = ['Feed', 'Count']

with open('/tmp/total.txt') as f:
    lines = f.readlines()
    total_iocs = int(lines[1].strip())

print("Data loaded successfully!")
print(f"Total IOCs: {total_iocs:,}")

# Set style
plt.style.use('dark_background')
fig = plt.figure(figsize=(20, 14))
fig.patch.set_facecolor('#0d1117')
fig.suptitle('MISP Threat Intelligence Platform — IOC Dashboard',
             fontsize=24, fontweight='bold', color='white', y=0.98)

colors = ['#ff6b6b','#feca57','#48dbfb','#ff9ff3','#54a0ff','#5f27cd','#00d2d3','#ff9f43','#1dd1a1','#c8d6e5']

# ── Chart 1: IOC Type Pie ──
ax1 = fig.add_subplot(2, 3, 1)
wedges, texts, autotexts = ax1.pie(
    df_types['Count'], labels=df_types['Type'],
    autopct='%1.1f%%', colors=colors[:len(df_types)],
    startangle=90, textprops={'color':'white','fontsize':8})
ax1.set_title('IOC Type Distribution', color='white', fontsize=13, fontweight='bold')

# ── Chart 2: IOC Types Bar ──
ax2 = fig.add_subplot(2, 3, 2)
bars = ax2.barh(df_types['Type'], df_types['Count'], color=colors[:len(df_types)])
ax2.set_xlabel('Count', color='white')
ax2.set_title('Top 10 IOC Types', color='white', fontsize=13, fontweight='bold')
ax2.tick_params(colors='white')
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)
ax2.spines['bottom'].set_color('#333')
ax2.spines['left'].set_color('#333')
for bar, val in zip(bars, df_types['Count']):
    ax2.text(val + 500, bar.get_y() + bar.get_height()/2,
             f'{val:,}', va='center', color='white', fontsize=8)

# ── Chart 3: Category Distribution ──
ax3 = fig.add_subplot(2, 3, 3)
bars3 = ax3.bar(range(len(df_cats)), df_cats['Count'], color=colors[:len(df_cats)])
ax3.set_xticks(range(len(df_cats)))
ax3.set_xticklabels(df_cats['Category'], rotation=45, ha='right', color='white', fontsize=8)
ax3.set_title('IOC Category Distribution', color='white', fontsize=13, fontweight='bold')
ax3.tick_params(colors='white')
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)
ax3.spines['bottom'].set_color('#333')
ax3.spines['left'].set_color('#333')

# ── Chart 4: Top Feed Sources ──
ax4 = fig.add_subplot(2, 3, 4)
df_feeds['Feed'] = df_feeds['Feed'].str[:35]
bars4 = ax4.barh(df_feeds['Feed'], df_feeds['Count'], color='#ff6b6b')
ax4.set_xlabel('IOC Count', color='white')
ax4.set_title('Top Feed Sources by IOC Count', color='white', fontsize=13, fontweight='bold')
ax4.tick_params(colors='white', labelsize=8)
ax4.spines['top'].set_visible(False)
ax4.spines['right'].set_visible(False)
ax4.spines['bottom'].set_color('#333')
ax4.spines['left'].set_color('#333')

# ── Chart 5: IOC Type Donut ──
ax5 = fig.add_subplot(2, 3, 5)
top5 = df_types.head(5)
other_count = df_types.iloc[5:]['Count'].sum()
labels = list(top5['Type']) + ['Others']
sizes = list(top5['Count']) + [other_count]
wedges2, texts2, autotexts2 = ax5.pie(
    sizes, labels=labels, autopct='%1.1f%%',
    colors=colors[:len(labels)], startangle=90,
    wedgeprops=dict(width=0.5),
    textprops={'color':'white','fontsize':9})
ax5.set_title('IOC Type Donut (Top 5)', color='white', fontsize=13, fontweight='bold')

# ── Chart 6: Stats Summary ──
ax6 = fig.add_subplot(2, 3, 6)
ax6.set_facecolor('#161b22')
ax6.axis('off')
stats = [
    ('Total IOCs', f'{total_iocs:,}', '#48dbfb'),
    ('IOC Types', f'{len(df_types)}', '#feca57'),
    ('Feed Sources', f'{len(df_feeds)}', '#ff9ff3'),
    ('Top IOC Type', df_types.iloc[0]["Type"], '#54a0ff'),
    ('Platform', 'MISP 2.5.39', '#ff6b6b'),
    ('Deployment', 'Docker + WSL2', '#00d2d3'),
    ('Cost', 'Zero (₹0)', '#1dd1a1'),
]
for i, (label, value, color) in enumerate(stats):
    y_pos = 0.88 - i * 0.12
    ax6.text(0.05, y_pos, label + ':', transform=ax6.transAxes,
             fontsize=12, color='#aaaaaa', fontweight='bold')
    ax6.text(0.55, y_pos, str(value), transform=ax6.transAxes,
             fontsize=12, color=color, fontweight='bold')
ax6.set_title('Platform Statistics', color='white', fontsize=13, fontweight='bold')

# Footer
fig.text(0.5, 0.01,
         f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} | '
         f'MISP on Docker+WSL2 | Author: Mrutyunjaya Muduli | CTI Analyst',
         ha='center', color='#666', fontsize=9)

plt.tight_layout(rect=[0, 0.02, 1, 0.96])
output_path = '/home/mrutyu1998/misp-dashboard.png'
plt.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor='#0d1117', edgecolor='none')
print(f"Dashboard saved to: {output_path}")
