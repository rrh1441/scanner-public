import { LRUCache } from 'lru-cache';
import type { CacheKey, CacheStats, ICache } from './index.js';

export class UnifiedCache implements ICache<any> {
  private lru: LRUCache<string, Buffer>;
  private hits = 0;
  private requests = 0;
  private readonly maxMemoryMB: number;

  constructor(config: {
    maxEntries?: number;
    maxMemoryMB?: number;
    defaultTtlMs?: number;
  } = {}) {
    this.maxMemoryMB = config.maxMemoryMB || 100;
    
    this.lru = new LRUCache<string, Buffer>({
      max: config.maxEntries || 10_000,
      maxSize: this.maxMemoryMB * 1024 * 1024, // Convert MB to bytes
      sizeCalculation: (val: Buffer) => val.length,
      ttl: config.defaultTtlMs || 24 * 60 * 60 * 1000, // 24 hours default
      allowStale: false,
      updateAgeOnGet: true,
      updateAgeOnHas: false,
    });
  }

  private serializeKey(key: CacheKey): string {
    // Create deterministic string from typed key
    switch (key.type) {
      case 'osv':
        return `osv:${key.ecosystem}:${key.package}:${key.version}`;
      case 'github':
        return `github:${key.ecosystem}:${key.package}:${key.version}`;
      case 'epss':
        return `epss:${key.cveId}`;
      case 'kev':
        return `kev:${key.cveId}`;
      case 'eol':
        return `eol:${key.slug}:${key.major}`;
      case 'deps_dev':
        return `deps_dev:${key.ecosystem}:${key.package}`;
      default:
        // TypeScript exhaustiveness check
        const _exhaustive: never = key;
        throw new Error(`Unknown cache key type: ${JSON.stringify(key)}`);
    }
  }

  async get<T>(key: CacheKey): Promise<T | null> {
    this.requests++;
    const stringKey = this.serializeKey(key);
    const buffer = this.lru.get(stringKey);
    
    if (buffer) {
      this.hits++;
      try {
        return JSON.parse(buffer.toString('utf8'));
      } catch (error) {
        // Corrupted cache entry, remove it
        this.lru.delete(stringKey);
        return null;
      }
    }
    
    return null;
  }

  async set(key: CacheKey, value: any, ttl?: number): Promise<void> {
    const stringKey = this.serializeKey(key);
    const jsonString = JSON.stringify(value);
    const buffer = Buffer.from(jsonString, 'utf8');
    
    // Check if this single entry would exceed our memory limit
    const entrySize = buffer.length;
    const maxSize = this.maxMemoryMB * 1024 * 1024;
    
    if (entrySize > maxSize * 0.1) { // Don't allow single entry > 10% of total cache
      console.warn(`Cache entry too large (${entrySize} bytes), skipping: ${stringKey}`);
      return;
    }
    
    this.lru.set(stringKey, buffer, { ttl });
  }

  stats(): CacheStats {
    const hitRate = this.requests > 0 ? this.hits / this.requests : 0;
    
    return {
      size: this.lru.size,
      hitRate: Math.round(hitRate * 100) / 100,
      totalRequests: this.requests,
      totalHits: this.hits,
      memoryUsageMB: Math.round((this.lru.calculatedSize || 0) / (1024 * 1024) * 100) / 100,
    };
  }

  async clear(): Promise<void> {
    this.lru.clear();
    this.hits = 0;
    this.requests = 0;
  }

  // Additional utility methods for monitoring
  logStats(prefix = '[UnifiedCache]'): void {
    const stats = this.stats();
    console.log(`${prefix} Stats:`, {
      entries: stats.size,
      hitRate: `${(stats.hitRate * 100).toFixed(1)}%`,
      memoryMB: stats.memoryUsageMB,
      maxMemoryMB: this.maxMemoryMB,
    });
  }
} 