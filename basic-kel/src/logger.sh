#!/bin/bash

# Check if the output filename is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <output_filename>"
    exit 1
fi

# Output file
output_file="$1"

while true; do
    # Get the current time
    current_time=$(date +"%Y-%m-%d %H:%M:%S")

    # Get the CPU usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    
    # Get the memory usage percentage and absolute value in bytes
    memory_info=$(free -b | grep Mem)
    memory_usage_percent=$(echo $memory_info | awk '{print $3/$2 * 100.0}')
    memory_used_bytes=$(echo $memory_info | awk '{print $3}')
    
    # Get the network usage
    bytes_sent=$(ifconfig | grep 'TX packets' | awk '{print $5}' | paste -sd+ | bc)
    bytes_recv=$(ifconfig | grep 'RX packets' | awk '{print $5}' | paste -sd+ | bc)
    
    # Write the information to the file
    echo "$current_time,$cpu_usage,$memory_usage_percent,$memory_used_bytes,$bytes_sent,$bytes_recv" >> "$output_file"
    
    # Wait for 5 seconds
    sleep 5
done