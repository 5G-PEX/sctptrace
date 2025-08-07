import pandas as pd
import matplotlib.pyplot as plt

# Load the dataframe.
df = pd.read_csv('../output/rto.csv')

# Create a figure with three subplots without sharing the y-axis.
fig, axes = plt.subplots(1, 3, figsize=(18, 3))

# Box plot for RTO (ms)
df.boxplot(column='rto_ms', by='UEs', ax=axes[0], grid=False)
axes[0].set_title('RTO (ms) by Number of UEs')
axes[0].set_xlabel('Number of UEs')
axes[0].set_ylabel('Time (ms)')
axes[0].get_figure().suptitle('') # To suppress the main title

# Box plot for SRTT (ms)
df.boxplot(column='srtt_ms', by='UEs', ax=axes[1], grid=False)
axes[1].set_title('SRTT (ms) by Number of UEs')
axes[1].set_xlabel('Number of UEs')
axes[1].set_ylabel('Time (ms)')
axes[1].get_figure().suptitle('')

# Box plot for RTTVAR (ms)
df.boxplot(column='rttvar_ms', by='UEs', ax=axes[2], grid=False)
axes[2].set_title('RTTVAR (ms) by Number of UEs')
axes[2].set_xlabel('Number of UEs')
axes[2].set_ylabel('Time (ms)')
axes[2].get_figure().suptitle('')

plt.tight_layout()

# Save the plot.
plt.savefig('../output/rto_box_plots_unscaled.png')