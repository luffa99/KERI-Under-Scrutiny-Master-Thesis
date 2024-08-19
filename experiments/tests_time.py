import matplotlib.pyplot as plt
import numpy as np
from scipy.interpolate import UnivariateSpline

def plot_users_vs_time(data_sets, title, bar_positions, bar_values):
    """
    Plots multiple sets of user vs time data with a line of best fit for each set
    and adds vertical bars with a different y-axis scale.
    
    Parameters:
    data_sets (dict): Dictionary where keys are set names and values are tuples of (users, time).
    title (str): Title of the plot.
    bar_positions (list): Positions on the x-axis (number of users) where bars will be placed.
    bar_values (list): Heights of the bars.
    bar_label (str): Label for the bars' y-axis.
    """
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    colors = plt.cm.viridis(np.linspace(0, 1, len(data_sets)))

    # Create a secondary y-axis
    # ax2 = ax1.twinx()
    # ax2.bar(bar_positions, bar_values, width=400, color='green', alpha=0.2)
    # ax2.set_ylabel("Success rate")
    
    for idx, (set_name, (users, time)) in enumerate(data_sets.items()):
        # Scatter plot for the data points
        ax1.scatter(users, time, color=colors[idx], label=f'{set_name}')
        
        # Fit a spline to the data
        spline = UnivariateSpline(users, time, s=0)
        xs = np.linspace(min(users), max(users), 1000)
        ys = spline(xs)

        # Plot the line of best fit
        ax1.plot(xs, ys, color=colors[idx], linestyle='--')# label=f'{set_name} Trend')
    
    # Set labels for the primary y-axis
    ax1.set_xlabel('Number of Users (N_U)')
    ax1.set_ylabel('Time (ms)')
    ax1.set_title(title)
    
    # Show legends for both y-axes
    ax1.legend(loc='upper left')
    # ax2.legend(loc='upper right')
    
    # Display the grid
    ax1.grid(True)
    
    # Show the plot
    plt.show()

# Example data
data = {
    'Test 1 (Icp+Verification)': ([500, 1000, 2500, 4000, 5000, 7500, 10000], 
                                  [5626,5488,5458,6328,7697,17252,38238]),
    'Test 3 (Verification after rotation)': ([500, 1000, 2500, 4000, 5000, 7500, 10000], 
                                             [569,545,515,502,492,494,485]),
    'Test 4 (Rotation)': ([500, 1000, 2500, 4000, 5000, 7500, 10000], 
                          [1895,1863,2036,3389,6993,25771,51098]),
}

# Bar data
bar_positions = [500, 1000, 2500, 5000]
bar_values = [1,1,1,1]  # Example values for the bars

plot_users_vs_time(data, '3/4 Witnesses + 3/4 Watchers', bar_positions, bar_values)
