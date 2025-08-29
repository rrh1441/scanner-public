/**
 * Dynamic Browser Subsystem
 * 
 * Provides a singleton Puppeteer browser instance with semaphore-controlled page pooling
 * to eliminate resource waste from multiple Chrome spawns across scan modules.
 */

import type { Browser, Page, LaunchOptions } from 'puppeteer';
import puppeteer from 'puppeteer';
import { Mutex } from 'async-mutex';
import * as os from 'node:os';
import * as process from 'node:process';
import { logLegacy as rootLog } from '../core/logger.js';

const log = (...args: unknown[]) => rootLog('[dynamicBrowser]', ...args);

// Configuration
const DEFAULT_BROWSER_ARGS = [
  '--no-sandbox',
  '--disable-setuid-sandbox', 
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--disable-web-security',
  '--disable-features=VizDisplayCompositor',
  '--window-size=1920,1080',
  '--headless=new',
  '--disable-background-timer-throttling',
  '--disable-backgrounding-occluded-windows',
  '--disable-renderer-backgrounding'
];

const MEMORY_CHECK_INTERVAL_MS = 15_000; // 15 seconds
const MEMORY_RESTART_THRESHOLD_MB = 3_500; // 3.5 GB
const PAGE_LEAK_WARNING_MS = 5 * 60 * 1000; // 5 minutes
const METRICS_LOG_INTERVAL_MS = 30_000; // 30 seconds
const DEFAULT_PAGE_TIMEOUT_MS = 60_000; // 60 seconds
const DEFAULT_VIEWPORT = { width: 1280, height: 800 };

// Global state
let globalBrowser: Browser | null = null;
let browserLaunchMutex = new Mutex();
let pageSemaphore: Mutex | null = null;
let activePagesCount = 0;
let memoryCheckInterval: NodeJS.Timeout | null = null;
let metricsInterval: NodeJS.Timeout | null = null;
let isShuttingDown = false;

// Page tracking for leak detection
const pageStartTimes = new WeakMap<Page, number>();

/**
 * Initialize the page semaphore based on configuration
 */
function initializeSemaphore(): void {
  const envMaxPages = process.env.PUPPETEER_MAX_PAGES;
  const maxPages = envMaxPages ? parseInt(envMaxPages, 10) : Math.min(3, os.cpus().length);
  
  if (maxPages < 1) {
    throw new Error('PUPPETEER_MAX_PAGES must be >= 1');
  }
  
  log(`Initializing page semaphore with max ${maxPages} concurrent pages`);
  pageSemaphore = new Mutex();
}

/**
 * Check if Puppeteer is enabled
 */
function isPuppeteerEnabled(): boolean {
  return process.env.ENABLE_PUPPETEER !== '0';
}

/**
 * Get memory usage of the current process
 */
function getMemoryUsage(): { rss: number; heapUsed: number } {
  const usage = process.memoryUsage();
  return {
    rss: Math.round(usage.rss / 1024 / 1024), // MB
    heapUsed: Math.round(usage.heapUsed / 1024 / 1024) // MB
  };
}

/**
 * Monitor browser memory usage and restart if needed
 */
async function checkMemoryUsage(): Promise<void> {
  if (!globalBrowser || isShuttingDown) return;
  
  const { rss } = getMemoryUsage();
  
  if (rss > MEMORY_RESTART_THRESHOLD_MB) {
    log(`Memory usage ${rss}MB exceeds threshold ${MEMORY_RESTART_THRESHOLD_MB}MB, restarting browser`);
    
    try {
      await closeBrowser();
      // Browser will be recreated on next getBrowser() call
    } catch (error) {
      log(`Error during memory-triggered browser restart: ${(error as Error).message}`);
    }
  }
}

/**
 * Log browser metrics periodically - only when pages are active or memory is high
 */
function logBrowserMetrics(): void {
  if (isShuttingDown) return;
  
  const { rss, heapUsed } = getMemoryUsage();
  
  // Only log if pages are active OR memory usage is concerning
  if (activePagesCount > 0 || rss > 1000 || heapUsed > 500) {
    log(`Metrics: browser_rss_mb=${rss}, heap_used_mb=${heapUsed}, pages_open=${activePagesCount}`);
  }
}

/**
 * Create browser launch options
 */
function createLaunchOptions(overrides: Partial<LaunchOptions> = {}): LaunchOptions {
  const isDevelopment = process.env.NODE_ENV !== 'production';
  const isDebug = process.env.DEBUG_PUPPETEER === 'true';
  
  return {
    headless: !isDevelopment,
    args: [...DEFAULT_BROWSER_ARGS, ...(overrides.args || [])],
    dumpio: isDebug,
    protocolTimeout: 90_000,
    timeout: 60_000,
    devtools: isDevelopment && isDebug,
    ...overrides
  };
}

/**
 * Launch a new browser instance
 */
async function launchBrowser(overrides: Partial<LaunchOptions> = {}): Promise<Browser> {
  log('Launching new browser instance');
  
  const launchOptions = createLaunchOptions(overrides);
  const browser = await puppeteer.launch(launchOptions);
  
  // Set up browser event listeners
  browser.on('disconnected', () => {
    log('Browser disconnected');
    globalBrowser = null;
  });
  
  log('Browser launched successfully');
  return browser;
}

/**
 * Close the global browser instance
 */
async function closeBrowser(): Promise<void> {
  if (!globalBrowser) return;
  
  log('Closing browser instance');
  
  try {
    await globalBrowser.close();
  } catch (error) {
    log(`Error closing browser: ${(error as Error).message}`);
  } finally {
    globalBrowser = null;
  }
}

/**
 * Get or create the singleton browser instance
 */
export async function getBrowser(overrides: Partial<LaunchOptions> = {}): Promise<Browser> {
  if (!isPuppeteerEnabled()) {
    throw new Error('Puppeteer disabled');
  }
  
  return browserLaunchMutex.runExclusive(async () => {
    if (globalBrowser && globalBrowser.isConnected()) {
      return globalBrowser;
    }
    
    // Start monitoring intervals on first browser launch
    if (!memoryCheckInterval) {
      initializeSemaphore();
      memoryCheckInterval = setInterval(checkMemoryUsage, MEMORY_CHECK_INTERVAL_MS);
      metricsInterval = setInterval(logBrowserMetrics, METRICS_LOG_INTERVAL_MS);
    }
    
    globalBrowser = await launchBrowser(overrides);
    return globalBrowser;
  });
}

/**
 * Execute a function with a managed page instance
 */
export async function withPage<T>(
  fn: (page: Page) => Promise<T>,
  launchOverrides: Partial<LaunchOptions> = {}
): Promise<T> {
  if (!isPuppeteerEnabled()) {
    throw new Error('Puppeteer disabled');
  }
  
  // Ensure semaphore is initialized
  if (!pageSemaphore) {
    initializeSemaphore();
  }
  
  return pageSemaphore!.runExclusive(async () => {
    let page: Page | null = null;
    let retryCount = 0;
    const maxRetries = 1;
    
    while (retryCount <= maxRetries) {
      try {
        const browser = await getBrowser(launchOverrides);
        page = await browser.newPage();
        
        // Track page for leak detection and metrics
        pageStartTimes.set(page, Date.now());
        activePagesCount++;
        
        // Set default page configuration
        await page.setDefaultTimeout(DEFAULT_PAGE_TIMEOUT_MS);
        await page.setViewport(DEFAULT_VIEWPORT);
        
        // Set up page event listeners
        page.on('error', (error) => {
          log(`Page error: ${error.message}`);
        });
        
        page.on('pageerror', (error) => {
          log(`Page script error: ${error.message}`);
        });
        
        // Check for page leaks
        const startTime = pageStartTimes.get(page);
        if (startTime && Date.now() - startTime > PAGE_LEAK_WARNING_MS) {
          log(`Warning: Page has been open for more than 5 minutes`);
        }
        
        // Execute the user function
        const startNav = Date.now();
        const result = await fn(page);
        const navDuration = Date.now() - startNav;
        
        log(`Page operation completed in ${navDuration}ms`);
        return result;
        
      } catch (error) {
        const errorMessage = (error as Error).message;
        
        // Check for browser/target closed errors that warrant retry
        if (
          (errorMessage.includes('Target closed') || 
           errorMessage.includes('Browser closed') ||
           errorMessage.includes('Session closed')) &&
          retryCount < maxRetries
        ) {
          log(`Browser connection error (attempt ${retryCount + 1}/${maxRetries + 1}): ${errorMessage}`);
          
          // Close and restart browser
          await closeBrowser();
          retryCount++;
          continue;
        }
        
        // Re-throw non-recoverable errors or after max retries
        throw error;
        
      } finally {
        // Always clean up the page
        if (page) {
          try {
            pageStartTimes.delete(page);
            activePagesCount = Math.max(0, activePagesCount - 1);
            
            if (!page.isClosed()) {
              await page.close();
            }
          } catch (closeError) {
            log(`Error closing page: ${(closeError as Error).message}`);
          }
        }
      }
    }
    
    throw new Error(`Failed to execute page operation after ${maxRetries + 1} attempts`);
  });
}

/**
 * Get browser memory statistics
 */
export function getBrowserMemoryStats(): {
  rss: number;
  heapUsed: number;
  activePagesCount: number;
  browserConnected: boolean;
} {
  const { rss, heapUsed } = getMemoryUsage();
  
  return {
    rss,
    heapUsed,
    activePagesCount,
    browserConnected: globalBrowser?.isConnected() ?? false
  };
}

/**
 * Graceful shutdown handler
 */
async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  
  log(`Received ${signal}, shutting down browser gracefully`);
  isShuttingDown = true;
  
  // Clear intervals
  if (memoryCheckInterval) {
    clearInterval(memoryCheckInterval);
    memoryCheckInterval = null;
  }
  
  if (metricsInterval) {
    clearInterval(metricsInterval);
    metricsInterval = null;
  }
  
  // Close browser
  try {
    await closeBrowser();
    log('Browser shutdown complete');
  } catch (error) {
    log(`Error during browser shutdown: ${(error as Error).message}`);
  }
}

// Initialize process event handlers
function initializeProcessHandlers() {
  // Only set up in non-test environments and if process.on exists
  if (process.env.NODE_ENV !== 'test' && typeof process?.on === 'function') {
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('beforeExit', () => gracefulShutdown('beforeExit'));
    
    process.on('unhandledRejection', (reason) => {
      log(`Unhandled rejection: ${reason}`);
    });
  }
}

// Initialize handlers on module load
initializeProcessHandlers();