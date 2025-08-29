module.exports = {
  apps: [{
    name: 'scanner-local',
    script: 'dist/localServer.js',
    cwd: '/Users/ryanheger/scanner-local/apps/workers',
    
    // Production settings
    instances: 1,
    exec_mode: 'fork',
    
    // Environment
    env: {
      NODE_ENV: 'production',
      MAX_CONCURRENT_SCANS: 24,
      PORT: 8080
    },
    
    // Auto-restart configuration  
    autorestart: true,
    watch: false,
    max_memory_restart: '2G',
    
    // Restart policies
    min_uptime: '10s',
    max_restarts: 10,
    restart_delay: 4000,
    
    // Logging
    log_file: '/Users/ryanheger/scanner-local/logs/combined.log',
    out_file: '/Users/ryanheger/scanner-local/logs/out.log',
    error_file: '/Users/ryanheger/scanner-local/logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Process management
    kill_timeout: 5000,
    listen_timeout: 3000,
    
    // Health monitoring
    health_check_grace_period: 30000,
    
    // Advanced settings for stability
    node_args: ['--max-old-space-size=2048'],
    
    // Cron restart (optional - restart daily at 3 AM)
    cron_restart: '0 3 * * *'
  }]
}