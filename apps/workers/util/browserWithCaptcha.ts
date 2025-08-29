/**
 * Browser Integration with Captcha Solving
 * 
 * Extends the shared browser system with automatic captcha detection and solving
 * capabilities using 2captcha service.
 */

import type { Page } from 'puppeteer';
import { withPage } from './dynamicBrowser.js';
import { captchaSolver, solveRecaptcha, type CaptchaResult } from './captchaSolver.js';
import { logLegacy as rootLog } from '../core/logger.js';

const log = (...args: unknown[]) => rootLog('[browserWithCaptcha]', ...args);

export interface CaptchaDetectionResult {
  detected: boolean;
  type?: 'recaptcha-v2' | 'recaptcha-v3' | 'hcaptcha' | 'cloudflare-turnstile' | 'unknown';
  sitekey?: string;
  selector?: string;
  invisible?: boolean;
}

export interface BrowserCaptchaOptions {
  /**
   * Maximum time to wait for captcha detection (ms)
   */
  detectionTimeout?: number;
  
  /**
   * Whether to automatically solve detected captchas
   */
  autoSolve?: boolean;
  
  /**
   * Maximum number of captcha solve attempts
   */
  maxSolveAttempts?: number;
  
  /**
   * Custom user agent to use for captcha solving
   */
  userAgent?: string;
  
  /**
   * Whether to wait for navigation after captcha solving
   */
  waitForNavigation?: boolean;
  
  /**
   * Timeout for navigation wait (ms)
   */
  navigationTimeout?: number;
}

const DEFAULT_OPTIONS: Required<BrowserCaptchaOptions> = {
  detectionTimeout: 5000,
  autoSolve: true,
  maxSolveAttempts: 3,
  userAgent: '',
  waitForNavigation: true,
  navigationTimeout: 30000
};

/**
 * Navigate to a URL with automatic captcha handling
 */
export async function navigateWithCaptchaHandling(
  url: string, 
  options: BrowserCaptchaOptions = {}
): Promise<{ success: boolean; captchaSolved?: boolean; error?: string }> {
  
  const config = { ...DEFAULT_OPTIONS, ...options };
  
  return withPage(async (page: Page) => {
    try {
      log(`navigate=start url="${url}"`);
      
      // Set user agent if provided
      if (config.userAgent) {
        await page.setUserAgent(config.userAgent);
      }
      
      // Navigate to the page
      await page.goto(url, { 
        waitUntil: 'networkidle2',
        timeout: config.navigationTimeout 
      });
      
      // Wait a moment for any dynamic content to load
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Detect captchas
      const captchaDetection = await detectCaptchas(page);
      
      if (!captchaDetection.detected) {
        log(`navigate=success url="${url}" captcha=none`);
        return { success: true, captchaSolved: false };
      }
      
      log(`navigate=captcha_detected url="${url}" type="${captchaDetection.type}" sitekey="${captchaDetection.sitekey}"`);
      
      if (!config.autoSolve) {
        return { 
          success: false, 
          error: `Captcha detected but auto-solve disabled: ${captchaDetection.type}` 
        };
      }
      
      // Attempt to solve the captcha
      const solveResult = await solveCaptchaOnPage(page, url, captchaDetection, config);
      
      if (solveResult.success) {
        log(`navigate=captcha_solved url="${url}" type="${captchaDetection.type}"`);
        return { success: true, captchaSolved: true };
      } else {
        log(`navigate=captcha_failed url="${url}" error="${solveResult.error}"`);
        return { 
          success: false, 
          captchaSolved: false, 
          error: `Captcha solving failed: ${solveResult.error}` 
        };
      }
      
    } catch (error) {
      const errorMessage = (error as Error).message;
      log(`navigate=error url="${url}" error="${errorMessage}"`);
      return { 
        success: false, 
        error: errorMessage 
      };
    }
  });
}

/**
 * Detect captchas on the current page
 */
export async function detectCaptchas(page: Page): Promise<CaptchaDetectionResult> {
  try {
    // Check for reCAPTCHA v2
    const recaptchaV2 = await page.evaluate(() => {
      // Look for reCAPTCHA v2 elements
      const iframe = document.querySelector('iframe[src*="recaptcha/api2/anchor"]');
      const container = document.querySelector('.g-recaptcha');
      const scriptTag = document.querySelector('script[src*="recaptcha/api.js"]');
      
      if (iframe || container || scriptTag) {
        // Try to find the sitekey
        let sitekey = '';
        
        // Check data-sitekey attribute
        const sitekeyElement = document.querySelector('[data-sitekey]');
        if (sitekeyElement) {
          sitekey = sitekeyElement.getAttribute('data-sitekey') || '';
        }
        
        // Check iframe src for sitekey
        if (!sitekey && iframe) {
          const src = iframe.getAttribute('src');
          const match = src?.match(/k=([^&]+)/);
          if (match) {
            sitekey = match[1];
          }
        }
        
        return {
          detected: true,
          type: 'recaptcha-v2' as const,
          sitekey,
          selector: container?.tagName.toLowerCase() || 'iframe',
          invisible: container?.getAttribute('data-size') === 'invisible'
        };
      }
      
      return null;
    });
    
    if (recaptchaV2) {
      return recaptchaV2;
    }
    
    // Check for hCaptcha
    const hcaptcha = await page.evaluate(() => {
      const container = document.querySelector('.h-captcha');
      const scriptTag = document.querySelector('script[src*="hcaptcha.com"]');
      
      if (container || scriptTag) {
        const sitekey = container?.getAttribute('data-sitekey') || '';
        
        return {
          detected: true,
          type: 'hcaptcha' as const,
          sitekey,
          selector: '.h-captcha'
        };
      }
      
      return null;
    });
    
    if (hcaptcha) {
      return hcaptcha;
    }
    
    // Check for Cloudflare Turnstile
    const turnstile = await page.evaluate(() => {
      const container = document.querySelector('.cf-turnstile');
      const scriptTag = document.querySelector('script[src*="challenges.cloudflare.com"]');
      
      if (container || scriptTag) {
        const sitekey = container?.getAttribute('data-sitekey') || '';
        
        return {
          detected: true,
          type: 'cloudflare-turnstile' as const,
          sitekey,
          selector: '.cf-turnstile'
        };
      }
      
      return null;
    });
    
    if (turnstile) {
      return turnstile;
    }
    
    // Check for generic captcha indicators
    const genericCaptcha = await page.evaluate(() => {
      const indicators = [
        'captcha',
        'challenge',
        'verification',
        'robot',
        'human'
      ];
      
      for (const indicator of indicators) {
        const element = document.querySelector(`[class*="${indicator}"], [id*="${indicator}"]`);
        if (element) {
          return {
            detected: true,
            type: 'unknown' as const,
            selector: element.tagName.toLowerCase()
          };
        }
      }
      
      return null;
    });
    
    if (genericCaptcha) {
      return genericCaptcha;
    }
    
    return { detected: false };
    
  } catch (error) {
    log(`detect=error error="${(error as Error).message}"`);
    return { detected: false };
  }
}

/**
 * Solve captcha on the current page
 */
async function solveCaptchaOnPage(
  page: Page, 
  pageUrl: string, 
  detection: CaptchaDetectionResult,
  config: Required<BrowserCaptchaOptions>
): Promise<CaptchaResult> {
  
  if (!captchaSolver.isEnabled()) {
    return {
      success: false,
      error: 'Captcha solver not configured'
    };
  }
  
  if (detection.type === 'recaptcha-v2' && detection.sitekey) {
    // Get current user agent
    const userAgent = config.userAgent || await page.evaluate(() => navigator.userAgent);
    
    // Get cookies for the domain
    const cookies = await page.cookies();
    const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    
    // Solve reCAPTCHA
    const result = await solveRecaptcha(detection.sitekey, pageUrl, {
      invisible: detection.invisible,
      userAgent,
      cookies: cookieString
    });
    
    if (result.success && result.token) {
      // Inject the token into the page
      const injected = await page.evaluate((token, selector) => {
        try {
          // Try multiple methods to inject the token
          
          // Method 1: Direct textarea injection
          const textarea = document.querySelector('textarea[name="g-recaptcha-response"]');
          if (textarea) {
            (textarea as HTMLTextAreaElement).value = token;
          }
          
          // Method 2: Callback function
          if (typeof (window as any).grecaptcha !== 'undefined' && (window as any).grecaptcha.getResponse) {
            // Trigger callback if it exists
            const callback = document.querySelector(selector || '')?.getAttribute('data-callback');
            if (callback && typeof (window as any)[callback] === 'function') {
              (window as any)[callback](token);
            }
          }
          
          // Method 3: Dispatch change event
          if (textarea) {
            const event = new Event('change', { bubbles: true });
            textarea.dispatchEvent(event);
          }
          
          return true;
        } catch (error) {
          console.error('Token injection failed:', error);
          return false;
        }
      }, result.token, detection.selector);
      
      if (injected) {
        // Wait for any form submission or navigation
        if (config.waitForNavigation) {
          try {
            await Promise.race([
              page.waitForNavigation({ timeout: config.navigationTimeout }),
              new Promise(resolve => setTimeout(resolve, 5000)) // Fallback timeout
            ]);
          } catch {
            // Navigation timeout is not critical
          }
        }
        
        return result;
      } else {
        return {
          success: false,
          error: 'Failed to inject captcha token into page'
        };
      }
    }
    
    return result;
  }
  
  return {
    success: false,
    error: `Unsupported captcha type: ${detection.type}`
  };
}

/**
 * Check if a page contains captchas
 */
export async function pageHasCaptcha(url: string): Promise<boolean> {
  return withPage(async (page: Page) => {
    try {
      await page.goto(url, { waitUntil: 'networkidle2' });
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const detection = await detectCaptchas(page);
      return detection.detected;
      
    } catch (error) {
      log(`check=error url="${url}" error="${(error as Error).message}"`);
      return false;
    }
  });
}

/**
 * Get captcha statistics for a domain
 */
export async function getCaptchaStats(domain: string): Promise<{
  hasCaptcha: boolean;
  captchaType?: string;
  sitekey?: string;
  cost?: number;
}> {
  
  const urls = [
    `https://${domain}`,
    `https://www.${domain}`,
    `https://${domain}/login`,
    `https://${domain}/register`,
    `https://${domain}/contact`
  ];
  
  for (const url of urls) {
    try {
      const detection = await withPage(async (page: Page) => {
        await page.goto(url, { 
          waitUntil: 'networkidle2',
          timeout: 15000 
        });
        await new Promise(resolve => setTimeout(resolve, 2000));
        return detectCaptchas(page);
      });
      
      if (detection.detected) {
        // Estimate cost based on captcha type
        let cost = 0;
        switch (detection.type) {
          case 'recaptcha-v2':
            cost = 0.002; // $0.002 per solve
            break;
          case 'hcaptcha':
            cost = 0.002;
            break;
          case 'cloudflare-turnstile':
            cost = 0.003;
            break;
          default:
            cost = 0.005; // Unknown type, assume higher cost
        }
        
        return {
          hasCaptcha: true,
          captchaType: detection.type,
          sitekey: detection.sitekey,
          cost
        };
      }
    } catch (error) {
      log(`stats=error url="${url}" error="${(error as Error).message}"`);
      continue;
    }
  }
  
  return { hasCaptcha: false };
}