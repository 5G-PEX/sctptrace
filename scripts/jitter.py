import pandas as pd
import matplotlib.pyplot as plt

# Load the dataframe.
df = pd.read_csv('../output/jitter.csv')

# Create a figure with two subplots.
plt.figure(figsize=(8, 4))

plt.plot(df['UEs'], df['delta_avg_us'], marker='o', label='Delta Avg (µs)')
plt.plot(df['UEs'], df['jitter_us'], marker='^', label='Jitter (µs)')
plt.title('Jitter Metrics vs. Number of UEs')
plt.xlabel('Number of UEs')
plt.ylabel('Time (µs)')
plt.legend()
plt.grid(True)

plt.tight_layout()

# Save the plot.
plt.savefig('../output/jitter_correlation_plot.png')