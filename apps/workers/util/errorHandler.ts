/* =============================================================================
 * UTILITY: errorHandler.ts
 * =============================================================================
 * Standardized error handling patterns for all worker modules.
 * Provides consistent logging, artifact creation, retry logic, and return patterns.
 * =============================================================================
 */

import { insertArtifact } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';

// ───────────────── Core Types ────────────────────────────────────────────
export interface ErrorContext {
  scanId?: string;
  moduleName: string;
  operation?: string;
  target?: string;
  metadata?: Record<string, unknown>;
}

export interface RetryConfig {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  exponentialBackoff: boolean;
  retryableErrors?: string[];
}

export interface ScanErrorResult {
  success: false;
  error: string;
  errorCode?: string;
  attempts?: number;
}

export interface ScanSuccessResult<T = unknown> {
  success: true;
  data: T;
  attempts?: number;
}

export type ScanResult<T = unknown> = ScanSuccessResult<T> | ScanErrorResult;

// ───────────────── Default Configurations ──────────────────────────────────
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  exponentialBackoff: true,
  retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', '429', '502', '503', '504']
};

// ───────────────── Error Handling Utility Class ────────────────────────────
export class StandardErrorHandler {
  private static instance: StandardErrorHandler;
  
  static getInstance(): StandardErrorHandler {
    if (!StandardErrorHandler.instance) {
      StandardErrorHandler.instance = new StandardErrorHandler();
    }
    return StandardErrorHandler.instance;
  }

  /**
   * Enhanced logging with structured context
   */
  logError(error: Error, context: ErrorContext, level: 'error' | 'warn' | 'info' = 'error'): void {
    const log = (...args: unknown[]) => rootLog(`[${context.moduleName}]`, ...args);
    
    const errorData = {
      message: error.message,
      name: error.name,
      stack: error.stack,
      operation: context.operation,
      target: context.target,
      metadata: context.metadata
    };

    if (level === 'error') {
      log(`ERROR: ${error.message}`, errorData);
    } else if (level === 'warn') {
      log(`WARN: ${error.message}`, errorData);
    } else {
      log(`INFO: ${error.message}`, errorData);
    }
  }

  /**
   * Create standardized scan_error artifact
   */
  async createErrorArtifact(
    error: Error, 
    context: ErrorContext, 
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM',
    scanDurationMs?: number
  ): Promise<void> {
    if (!context.scanId) return;

    const artifactText = context.operation 
      ? `${context.operation} failed: ${error.message}`
      : `${context.moduleName} scan failed: ${error.message}`;

    await insertArtifact({
      type: 'scan_error',
      val_text: artifactText,
      severity,
      meta: {
        scan_id: context.scanId,
        scan_module: context.moduleName,
        error: true,
        error_message: error.message,
        error_name: error.name,
        operation: context.operation,
        target: context.target,
        scan_duration_ms: scanDurationMs,
        metadata: context.metadata
      }
    });
  }

  /**
   * Determine if an error is retryable based on configuration
   */
  isRetryableError(error: Error, retryConfig: RetryConfig): boolean {
    const errorMessage = error.message.toLowerCase();
    const errorName = error.name.toLowerCase();
    
    return retryConfig.retryableErrors?.some(retryableError => 
      errorMessage.includes(retryableError.toLowerCase()) ||
      errorName.includes(retryableError.toLowerCase())
    ) ?? false;
  }

  /**
   * Calculate delay for retry with exponential backoff
   */
  calculateRetryDelay(attempt: number, config: RetryConfig): number {
    if (!config.exponentialBackoff) {
      return Math.min(config.baseDelayMs, config.maxDelayMs);
    }
    
    const delay = config.baseDelayMs * Math.pow(2, attempt - 1);
    return Math.min(delay, config.maxDelayMs);
  }

  /**
   * Execute operation with retry logic
   */
  async withRetry<T>(
    operation: () => Promise<T>,
    context: ErrorContext,
    retryConfig: Partial<RetryConfig> = {}
  ): Promise<ScanResult<T>> {
    const config = { ...DEFAULT_RETRY_CONFIG, ...retryConfig };
    const log = (...args: unknown[]) => rootLog(`[${context.moduleName}]`, ...args);
    
    let lastError: Error;
    
    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
      try {
        const result = await operation();
        
        if (attempt > 1) {
          log(`operation="${context.operation}" succeeded after ${attempt} attempts`);
        }
        
        return { success: true, data: result, attempts: attempt };
        
      } catch (error) {
        lastError = error as Error;
        this.logError(lastError, context, attempt === config.maxAttempts ? 'error' : 'warn');
        
        // Don't retry on final attempt
        if (attempt === config.maxAttempts) {
          break;
        }
        
        // Check if error is retryable
        if (!this.isRetryableError(lastError, config)) {
          log(`operation="${context.operation}" non-retryable error, aborting retries`);
          break;
        }
        
        // Calculate and wait for retry delay
        const delay = this.calculateRetryDelay(attempt, config);
        log(`operation="${context.operation}" attempt ${attempt} failed, retrying in ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    return { 
      success: false, 
      error: lastError!.message,
      errorCode: lastError!.name,
      attempts: config.maxAttempts
    };
  }

  /**
   * Standardized module execution wrapper
   */
  async executeModule<T>(
    moduleName: string,
    operation: () => Promise<T>,
    context: Omit<ErrorContext, 'moduleName'> = {}
  ): Promise<T> {
    const startTime = Date.now();
    const fullContext: ErrorContext = { ...context, moduleName };
    const log = (...args: unknown[]) => rootLog(`[${moduleName}]`, ...args);
    
    try {
      log(`starting operation="${context.operation || 'main'}"`);
      const result = await operation();
      
      const duration = Date.now() - startTime;
      log(`completed operation="${context.operation || 'main'}" duration=${duration}ms`);
      
      return result;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      const err = error as Error;
      
      this.logError(err, fullContext);
      
      // Create error artifact if scanId provided
      await this.createErrorArtifact(err, fullContext, 'MEDIUM', duration);
      
      // For module execution, we typically want to return a safe default (0 for findings count)
      // rather than throw, unless it's a critical system error
      if (this.isCriticalSystemError(err)) {
        throw err;
      }
      
      log(`module failed, returning safe default (0)`);
      return 0 as T;
    }
  }

  /**
   * Determine if error is a critical system error that should propagate
   */
  private isCriticalSystemError(error: Error): boolean {
    const criticalErrors = ['EACCES', 'EMFILE', 'ENOMEM', 'ENOSPC'];
    return criticalErrors.some(criticalError => 
      error.message.includes(criticalError) || error.name.includes(criticalError)
    );
  }
}

// ───────────────── Convenience Functions ────────────────────────────────────
export const errorHandler = StandardErrorHandler.getInstance();

/**
 * Convenience function for module execution
 */
export async function executeModule<T>(
  moduleName: string,
  operation: () => Promise<T>,
  context?: Omit<ErrorContext, 'moduleName'>
): Promise<T> {
  return errorHandler.executeModule(moduleName, operation, context);
}

/**
 * Convenience function for retry operations
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  context: ErrorContext,
  retryConfig?: Partial<RetryConfig>
): Promise<ScanResult<T>> {
  return errorHandler.withRetry(operation, context, retryConfig);
}

/**
 * Convenience function for API calls with standard retry config
 */
export async function apiCall<T>(
  operation: () => Promise<T>,
  context: ErrorContext
): Promise<ScanResult<T>> {
  return errorHandler.withRetry(operation, context, {
    maxAttempts: 3,
    baseDelayMs: 1000,
    exponentialBackoff: true,
    retryableErrors: ['429', '502', '503', '504', 'ECONNRESET', 'ETIMEDOUT']
  });
}

/**
 * Convenience function for file operations with standard retry config
 */
export async function fileOperation<T>(
  operation: () => Promise<T>,
  context: ErrorContext
): Promise<ScanResult<T>> {
  return errorHandler.withRetry(operation, context, {
    maxAttempts: 2,
    baseDelayMs: 500,
    exponentialBackoff: false,
    retryableErrors: ['EBUSY', 'ENOENT', 'EMFILE']
  });
} 