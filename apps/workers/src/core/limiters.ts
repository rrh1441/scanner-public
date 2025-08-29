import PQueue from 'p-queue';

// Configuration from environment
const GLOBAL_NET_CONCURRENCY = parseInt(process.env.GLOBAL_NET_CONCURRENCY || '60');
const PER_HOST_CONCURRENCY = parseInt(process.env.PER_HOST_CONCURRENCY || '3');

// Global network limiter to prevent socket exhaustion
export const globalNetLimiter = new PQueue({
  concurrency: GLOBAL_NET_CONCURRENCY
});

// Per-host limiter registry to prevent hammering specific domains
const hostLimiters = new Map<string, PQueue>();

export function limiterForHost(hostname: string): PQueue {
  let limiter = hostLimiters.get(hostname);
  if (!limiter) {
    limiter = new PQueue({ concurrency: PER_HOST_CONCURRENCY });
    hostLimiters.set(hostname, limiter);
    console.log(`[Limiters] Created rate limiter for ${hostname} (max: ${PER_HOST_CONCURRENCY})`);
  }
  return limiter;
}

// Utility to get current limiter stats
export function getLimiterStats() {
  return {
    global: {
      size: globalNetLimiter.size,
      pending: globalNetLimiter.pending,
      concurrency: globalNetLimiter.concurrency
    },
    hosts: Array.from(hostLimiters.entries()).map(([hostname, limiter]) => ({
      hostname,
      size: limiter.size,
      pending: limiter.pending,
      concurrency: limiter.concurrency
    }))
  };
}