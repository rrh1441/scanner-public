// Unified cache interface with typed keys for techStackScan
export type CacheKey = 
  | { type: 'osv'; ecosystem: string; package: string; version: string }
  | { type: 'github'; ecosystem: string; package: string; version: string }
  | { type: 'epss'; cveId: string }
  | { type: 'kev'; cveId: string }
  | { type: 'eol'; slug: string; major: string }
  | { type: 'deps_dev'; ecosystem: string; package: string };

export interface CacheStats {
  size: number;
  hitRate: number;
  totalRequests: number;
  totalHits: number;
  memoryUsageMB: number;
}

export interface ICache<T> {
  get(key: CacheKey): Promise<T | null>;
  set(key: CacheKey, value: T, ttl?: number): Promise<void>;
  stats(): CacheStats;
  clear(): Promise<void>;
}

// Export the implementation
export { UnifiedCache } from './lruCache.js'; 