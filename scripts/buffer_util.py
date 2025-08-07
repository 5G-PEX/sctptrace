import pandas as pd
import matplotlib.pyplot as plt

# Load the dataframe.
df = pd.read_csv('../output/buffer_util.csv')

# Group the data by 'UEs' and calculate the mean for the relevant columns.
df_grouped = df.groupby('UEs').mean(numeric_only=True).reset_index()

# Create a scatter plot and a line plot for 'Avg_Util_%' vs 'UEs'.
plt.figure(figsize=(8, 4))

plt.plot(df_grouped['UEs'], df_grouped['Avg_Util_%'], marker='o')
plt.title('Average Utilisation vs. Number of UEs (Line Plot)')
plt.xlabel('Number of UEs')
plt.ylabel('Average Utilisation (%)')
plt.grid(True)

plt.tight_layout()
plt.savefig('../output/buffutil_avg_util_vs_ues.png')

plt.figure(figsize=(8, 4))

plt.plot(df_grouped['UEs'], df_grouped['Avg_RWND_bytes'], marker='o')
plt.title('Average RWND Bytes vs. Number of UEs (Line Plot)')
plt.xlabel('Number of UEs')
plt.ylabel('Average RWND Bytes')
plt.grid(True)

plt.tight_layout()
plt.savefig('../output/buffutil_avg_rwnd_bytes_vs_ues.png')