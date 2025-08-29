#!/bin/bash
# Resource Monitor for Load Testing
# Monitors CPU, Memory, Database connections, and Node.js processes during concurrent scans

LOG_FILE="load-test-resources-$(date +%Y%m%d_%H%M%S).log"
INTERVAL=2  # Monitor every 2 seconds

echo "🔬 Resource Monitor Starting - Logging to $LOG_FILE"
echo "Monitor will track: CPU, Memory, PostgreSQL connections, Node.js processes"
echo "Press Ctrl+C to stop monitoring"

# Initialize log file with headers
cat > "$LOG_FILE" << EOF
# Resource Monitor Log - $(date)
# Columns: timestamp,cpu_percent,memory_used_gb,memory_percent,postgres_connections,node_processes,node_memory_mb
timestamp,cpu_percent,memory_used_gb,memory_percent,postgres_connections,node_processes,node_memory_mb
EOF

monitor_loop() {
    while true; do
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        
        # CPU Usage (system-wide)
        CPU_PERCENT=$(top -l 1 -s 0 | grep "CPU usage" | awk '{print $3}' | sed 's/%//')
        if [[ -z "$CPU_PERCENT" ]]; then
            CPU_PERCENT="0"
        fi
        
        # Memory Usage
        MEMORY_INFO=$(vm_stat | head -4)
        PAGE_SIZE=$(vm_stat | grep "page size" | awk '{print $8}')
        FREE_PAGES=$(echo "$MEMORY_INFO" | grep "Pages free" | awk '{print $3}' | sed 's/\.//')
        ACTIVE_PAGES=$(echo "$MEMORY_INFO" | grep "Pages active" | awk '{print $3}' | sed 's/\.//')
        INACTIVE_PAGES=$(echo "$MEMORY_INFO" | grep "Pages inactive" | awk '{print $3}' | sed 's/\.//')
        WIRED_PAGES=$(echo "$MEMORY_INFO" | grep "Pages wired down" | awk '{print $4}' | sed 's/\.//')
        
        # Calculate memory in GB
        TOTAL_MEMORY_GB=$(echo "scale=2; ($FREE_PAGES + $ACTIVE_PAGES + $INACTIVE_PAGES + $WIRED_PAGES) * $PAGE_SIZE / 1024 / 1024 / 1024" | bc)
        USED_MEMORY_GB=$(echo "scale=2; ($ACTIVE_PAGES + $INACTIVE_PAGES + $WIRED_PAGES) * $PAGE_SIZE / 1024 / 1024 / 1024" | bc)
        MEMORY_PERCENT=$(echo "scale=1; $USED_MEMORY_GB / $TOTAL_MEMORY_GB * 100" | bc)
        
        # PostgreSQL Connections
        PG_CONNECTIONS=$(psql -d scanner_local -t -c "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = 'scanner_local';" 2>/dev/null || echo "0")
        PG_CONNECTIONS=$(echo $PG_CONNECTIONS | xargs)  # Trim whitespace
        
        # Node.js Processes and Memory
        NODE_PROCESSES=$(pgrep -c node || echo "0")
        NODE_MEMORY_MB=0
        if [[ $NODE_PROCESSES -gt 0 ]]; then
            # Get memory usage of all node processes in MB
            NODE_MEMORY_KB=$(ps -o pid,rss -p $(pgrep node | tr '\n' ',' | sed 's/,$//') 2>/dev/null | tail -n +2 | awk '{sum+=$2} END {print sum}')
            if [[ -n "$NODE_MEMORY_KB" && "$NODE_MEMORY_KB" -gt 0 ]]; then
                NODE_MEMORY_MB=$(echo "scale=0; $NODE_MEMORY_KB / 1024" | bc)
            fi
        fi
        
        # Log the data
        echo "$TIMESTAMP,$CPU_PERCENT,$USED_MEMORY_GB,$MEMORY_PERCENT,$PG_CONNECTIONS,$NODE_PROCESSES,$NODE_MEMORY_MB" >> "$LOG_FILE"
        
        # Display current stats
        printf "\r⏱️  %s | CPU: %s%% | RAM: %s/%sGB (%s%%) | PG: %s conn | Node: %s proc (%sMB)" \
            "$(date '+%H:%M:%S')" \
            "$CPU_PERCENT" \
            "$USED_MEMORY_GB" \
            "$TOTAL_MEMORY_GB" \
            "$MEMORY_PERCENT" \
            "$PG_CONNECTIONS" \
            "$NODE_PROCESSES" \
            "$NODE_MEMORY_MB"
        
        sleep $INTERVAL
    done
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n\n📊 Monitoring stopped. Log saved to: $LOG_FILE"; exit 0' SIGINT

# Start monitoring
monitor_loop