import pandas as pd
import matplotlib.pyplot as plt

# Load the dataframe.
df = pd.read_csv('../output/rtt.csv')

# Drop rows with any NaN values.
df = df.dropna()

# Convert 'UEs' column to integer type for clean grouping.
df['UEs'] = df['UEs'].astype(int)

# Group the data by 'UEs' and calculate the mean of RTT metrics.
grouped_data = df.groupby('UEs')[['rtt_avg_us', 'rtt_min_us', 'rtt_max_us']].mean().reset_index()

# Plot the data.
plt.figure(figsize=(8, 4))

plt.plot(grouped_data['UEs'], grouped_data['rtt_avg_us'], marker='o', label='RTT Avg (µs)')
plt.plot(grouped_data['UEs'], grouped_data['rtt_min_us'], marker='s', label='RTT Min (µs)')
plt.plot(grouped_data['UEs'], grouped_data['rtt_max_us'], marker='^', label='RTT Max (µs)')

# Add labels and title.
plt.xlabel('Number of UEs')
plt.ylabel('Time (µs)')
plt.title('Average RTT Metrics vs. Number of UEs')
plt.legend()
plt.grid(True)
plt.xticks(grouped_data['UEs'])

# Save the plot.
plt.savefig('../output/rtt_correlation_plot.png')