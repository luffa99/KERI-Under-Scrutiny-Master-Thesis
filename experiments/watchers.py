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


    my_xticks = ['3/4 {1}', '5/7 {2}', '6/8 {2}','7/10 {3}', '8/12 {3}']
    plt.xticks([0,1,2,3,4], my_xticks)

    # Create a secondary y-axis
    # ax2 = ax1.twinx()
    # ax2.bar(bar_positions, bar_values, width=0.2, color='green', alpha=0.2)
    # ax2.set_ylabel("Success rate")
    
    for idx, (set_name, (users, time)) in enumerate(data_sets.items()):
        # Scatter plot for the data points
        ax1.scatter(users, time, color=colors[idx], label=f'{set_name}')
        
        # Fit a spline to the data
        # spline = UnivariateSpline(users, time, s=0)
        # xs = np.linspace(min(users), max(users), 1000)
        # ys = spline(xs)

        # # Plot the line of best fit
        # ax1.plot(xs, ys, color=colors[idx], linestyle='--')# label=f'{set_name} Trend')
        ax1.plot(users, time, '-o', color=colors[idx])
    
    # Set labels for the primary y-axis
    ax1.set_xlabel('Watcher Setting {Fault-tolerance}')
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
    'Test 1 (Icp+Verification)': ([0,1,2,3,4], 
                                  [5488,7122,7990,8817,9863]),
    'Test 3 (Verification after rotation)': ([0,1,2,3,4], 
                                             [545,908,1122,1318,1638]),
    'Test 4 (Rotation)': ([0,1,2,3,4], 
                          [1863,1903,1898,1884,1934]),
}

# Bar data
bar_positions = [0,1,2,3,4]
bar_values = [1,1,1,1,1]  # Example values for the bars

plot_users_vs_time(data, '1000 users', bar_positions, bar_values)
