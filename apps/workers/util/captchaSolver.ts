/**
 * 2Captcha Integration Utility
 * 
 * Provides automated captcha solving capabilities for DealBrief scanning modules
 * using the 2captcha.com human-powered recognition service.
 */

import axios from 'axios';
import { logLegacy as rootLog } from '../core/logger.js';

const log = (...args: unknown[]) => rootLog('[captchaSolver]', ...args);

// Configuration
const CAPTCHA_CONFIG = {
  API_BASE_URL: 'https://2captcha.com',
  SUBMIT_ENDPOINT: '/in.php',
  RESULT_ENDPOINT: '/res.php',
  
  // Timeouts (reduced for test environment)
  RECAPTCHA_TIMEOUT_MS: process.env.NODE_ENV === 'test' ? 100 : 20_000,  // 20 seconds for reCAPTCHA, 100ms for tests
  NORMAL_TIMEOUT_MS: process.env.NODE_ENV === 'test' ? 50 : 5_000,       // 5 seconds for other captchas, 50ms for tests
  POLLING_INTERVAL_MS: process.env.NODE_ENV === 'test' ? 50 : 5_000,     // Check every 5 seconds, 50ms for tests
  MAX_POLLING_ATTEMPTS: process.env.NODE_ENV === 'test' ? 3 : 24,        // 2 minutes total wait time, 3 attempts for tests
  
  // API timeouts
  REQUEST_TIMEOUT_MS: 30_000,
  
  // Retry configuration
  MAX_RETRIES: 2,
  RETRY_DELAY_MS: 1_000
};

export interface CaptchaResult {
  success: boolean;
  token?: string;
  error?: string;
  taskId?: string;
  cost?: number;
  solveTime?: number;
}

export interface RecaptchaV2Options {
  sitekey: string;
  pageUrl: string;
  invisible?: boolean;
  enterprise?: boolean;
  data?: Record<string, string>;
  cookies?: string;
  userAgent?: string;
  proxy?: ProxyConfig;
}

export interface ProxyConfig {
  type: 'HTTP' | 'HTTPS' | 'SOCKS4' | 'SOCKS5';
  host: string;
  port: number;
  username?: string;
  password?: string;
}

export interface NormalCaptchaOptions {
  imageBase64?: string;
  imageUrl?: string;
  phrase?: boolean;        // Contains multiple words
  caseSensitive?: boolean; // Case sensitive
  numeric?: 0 | 1 | 2 | 3 | 4; // 0=not specified, 1=numbers only, 2=letters only, 3=numbers OR letters, 4=numbers AND letters
  calculation?: boolean;   // Requires math calculation
  minLength?: number;      // 1-20
  maxLength?: number;      // 1-20
  language?: string;       // Language code
  textInstructions?: string; // Instructions for worker
}

class CaptchaSolver {
  private apiKey: string;
  
  constructor() {
    this.apiKey = process.env.CAPTCHA_API_KEY || '';
    
    if (!this.apiKey) {
      log('WARNING: CAPTCHA_API_KEY not set - captcha solving will be disabled');
    }
  }

  /**
   * Check if captcha solving is enabled
   */
  isEnabled(): boolean {
    return !!this.apiKey;
  }

  /**
   * Get account balance
   */
  async getBalance(): Promise<number> {
    if (!this.isEnabled()) {
      throw new Error('Captcha solver not configured');
    }

    try {
      const response = await axios.get(`${CAPTCHA_CONFIG.API_BASE_URL}${CAPTCHA_CONFIG.RESULT_ENDPOINT}`, {
        params: {
          key: this.apiKey,
          action: 'getbalance'
        },
        timeout: CAPTCHA_CONFIG.REQUEST_TIMEOUT_MS
      });

      const result = response.data.toString().trim();
      
      if (result.startsWith('ERROR_')) {
        throw new Error(`2captcha API error: ${result}`);
      }

      return parseFloat(result);
    } catch (error) {
      log(`balance=error error="${(error as Error).message}"`);
      throw error;
    }
  }

  /**
   * Solve reCAPTCHA V2
   */
  async solveRecaptchaV2(options: RecaptchaV2Options): Promise<CaptchaResult> {
    const startTime = Date.now();
    
    if (!this.isEnabled()) {
      return {
        success: false,
        error: 'Captcha solver not configured'
      };
    }

    log(`recaptcha=start sitekey="${options.sitekey}" url="${options.pageUrl}"`);

    try {
      // Submit captcha
      const taskId = await this.submitRecaptchaV2(options);

      // Wait for initial timeout
      await this.delay(CAPTCHA_CONFIG.RECAPTCHA_TIMEOUT_MS);
      
      // Poll for result
      const result = await this.pollForResult(taskId);
      
      if (result.success) {
        const solveTime = Date.now() - startTime;
        log(`recaptcha=solved taskId="${taskId}" time=${solveTime}ms`);
        
        return {
          ...result,
          taskId,
          solveTime
        };
      }

      return result;

    } catch (error) {
      const errorMessage = (error as Error).message;
      log(`recaptcha=error sitekey="${options.sitekey}" error="${errorMessage}"`);
      
      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Solve normal image captcha
   */
  async solveNormalCaptcha(options: NormalCaptchaOptions): Promise<CaptchaResult> {
    const startTime = Date.now();
    
    if (!this.isEnabled()) {
      return {
        success: false,
        error: 'Captcha solver not configured'
      };
    }

    if (!options.imageBase64 && !options.imageUrl) {
      return {
        success: false,
        error: 'Either imageBase64 or imageUrl must be provided'
      };
    }

    log(`normal=start hasImage=${!!options.imageBase64} hasUrl=${!!options.imageUrl}`);

    try {
      // Submit captcha
      const taskId = await this.submitNormalCaptcha(options);

      // Wait for initial timeout
      await this.delay(CAPTCHA_CONFIG.NORMAL_TIMEOUT_MS);
      
      // Poll for result
      const result = await this.pollForResult(taskId);
      
      if (result.success) {
        const solveTime = Date.now() - startTime;
        log(`normal=solved taskId="${taskId}" time=${solveTime}ms`);
        
        return {
          ...result,
          taskId,
          solveTime
        };
      }

      return result;

    } catch (error) {
      const errorMessage = (error as Error).message;
      log(`normal=error error="${errorMessage}"`);
      
      return {
        success: false,
        error: errorMessage
      };
    }
  }

  /**
   * Submit reCAPTCHA V2 for solving
   */
  private async submitRecaptchaV2(options: RecaptchaV2Options): Promise<string> {
    const params: Record<string, string> = {
      key: this.apiKey,
      method: 'userrecaptcha',
      googlekey: options.sitekey,
      pageurl: options.pageUrl
    };

    // Add optional parameters
    if (options.invisible) {
      params.invisible = '1';
    }

    if (options.enterprise) {
      params.enterprise = '1';
    }

    if (options.data) {
      Object.entries(options.data).forEach(([key, value]) => {
        params[`data-${key}`] = value;
      });
    }

    if (options.cookies) {
      params.cookies = options.cookies;
    }

    if (options.userAgent) {
      params.userAgent = options.userAgent;
    }

    // Add proxy information
    if (options.proxy) {
      params.proxy = `${options.proxy.host}:${options.proxy.port}`;
      params.proxytype = options.proxy.type;
      
      if (options.proxy.username && options.proxy.password) {
        params.proxy = `${options.proxy.username}:${options.proxy.password}@${params.proxy}`;
      }
    }

    return this.submitCaptcha(params);
  }

  /**
   * Submit normal captcha for solving
   */
  private async submitNormalCaptcha(options: NormalCaptchaOptions): Promise<string> {
    const params: Record<string, string> = {
      key: this.apiKey,
      method: 'base64'
    };

    // Image data
    if (options.imageBase64) {
      params.body = options.imageBase64;
    } else if (options.imageUrl) {
      // For URL method, we would need to fetch the image and convert to base64
      // For now, throw an error
      throw new Error('Image URL method not implemented - use imageBase64 instead');
    }

    // Add optional parameters
    if (options.phrase) {
      params.phrase = '1';
    }

    if (options.caseSensitive) {
      params.regsense = '1';
    }

    if (options.numeric !== undefined) {
      params.numeric = options.numeric.toString();
    }

    if (options.calculation) {
      params.calc = '1';
    }

    if (options.minLength) {
      params.min_len = options.minLength.toString();
    }

    if (options.maxLength) {
      params.max_len = options.maxLength.toString();
    }

    if (options.language) {
      params.lang = options.language;
    }

    if (options.textInstructions) {
      params.textinstructions = options.textInstructions;
    }

    return this.submitCaptcha(params);
  }

  /**
   * Submit captcha to 2captcha API
   */
  private async submitCaptcha(params: Record<string, string>): Promise<string> {
    try {
      const response = await axios.post(
        `${CAPTCHA_CONFIG.API_BASE_URL}${CAPTCHA_CONFIG.SUBMIT_ENDPOINT}`,
        new URLSearchParams(params).toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: CAPTCHA_CONFIG.REQUEST_TIMEOUT_MS
        }
      );

      const result = response.data.toString().trim();
      
      if (result.startsWith('ERROR_')) {
        throw new Error(`2captcha submission error: ${result}`);
      }

      if (result.startsWith('OK|')) {
        const taskId = result.substring(3);
        log(`submit=success taskId="${taskId}"`);
        return taskId;
      }

      throw new Error(`Unexpected response: ${result}`);

    } catch (error) {
      const errorMessage = (error as Error).message;
      log(`submit=error error="${errorMessage}"`);
      
      // Re-throw the original error instead of returning null
      // so the specific error message is preserved
      throw error;
    }
  }

  /**
   * Poll for captcha result
   */
  private async pollForResult(taskId: string): Promise<CaptchaResult> {
    let attempts = 0;

    while (attempts < CAPTCHA_CONFIG.MAX_POLLING_ATTEMPTS) {
      try {
        const response = await axios.get(`${CAPTCHA_CONFIG.API_BASE_URL}${CAPTCHA_CONFIG.RESULT_ENDPOINT}`, {
          params: {
            key: this.apiKey,
            action: 'get',
            id: taskId
          },
          timeout: CAPTCHA_CONFIG.REQUEST_TIMEOUT_MS
        });

        const result = response.data.toString().trim();
        
        if (result === 'CAPCHA_NOT_READY') {
          attempts++;
          log(`poll=waiting taskId="${taskId}" attempt=${attempts}/${CAPTCHA_CONFIG.MAX_POLLING_ATTEMPTS}`);
          await this.delay(CAPTCHA_CONFIG.POLLING_INTERVAL_MS);
          continue;
        }

        if (result.startsWith('ERROR_')) {
          return {
            success: false,
            error: `2captcha result error: ${result}`
          };
        }

        if (result.startsWith('OK|')) {
          const token = result.substring(3);
          log(`poll=solved taskId="${taskId}"`);
          
          return {
            success: true,
            token
          };
        }

        return {
          success: false,
          error: `Unexpected response: ${result}`
        };

      } catch (error) {
        log(`poll=error taskId="${taskId}" error="${(error as Error).message}"`);
        
        attempts++;
        if (attempts >= CAPTCHA_CONFIG.MAX_POLLING_ATTEMPTS) {
          return {
            success: false,
            error: 'Polling timeout exceeded'
          };
        }
        
        await this.delay(CAPTCHA_CONFIG.POLLING_INTERVAL_MS);
      }
    }

    return {
      success: false,
      error: 'Maximum polling attempts exceeded'
    };
  }

  /**
   * Report bad captcha result
   */
  async reportBad(taskId: string): Promise<boolean> {
    if (!this.isEnabled()) {
      return false;
    }

    try {
      const response = await axios.get(`${CAPTCHA_CONFIG.API_BASE_URL}${CAPTCHA_CONFIG.RESULT_ENDPOINT}`, {
        params: {
          key: this.apiKey,
          action: 'reportbad',
          id: taskId
        },
        timeout: CAPTCHA_CONFIG.REQUEST_TIMEOUT_MS
      });

      const result = response.data.toString().trim();
      
      if (result === 'OK_REPORT_RECORDED') {
        log(`report=bad taskId="${taskId}"`);
        return true;
      }

      log(`report=failed taskId="${taskId}" result="${result}"`);
      return false;

    } catch (error) {
      log(`report=error taskId="${taskId}" error="${(error as Error).message}"`);
      return false;
    }
  }

  /**
   * Report good captcha result
   */
  async reportGood(taskId: string): Promise<boolean> {
    if (!this.isEnabled()) {
      return false;
    }

    try {
      const response = await axios.get(`${CAPTCHA_CONFIG.API_BASE_URL}${CAPTCHA_CONFIG.RESULT_ENDPOINT}`, {
        params: {
          key: this.apiKey,
          action: 'reportgood',
          id: taskId
        },
        timeout: CAPTCHA_CONFIG.REQUEST_TIMEOUT_MS
      });

      const result = response.data.toString().trim();
      
      if (result === 'OK_REPORT_RECORDED') {
        log(`report=good taskId="${taskId}"`);
        return true;
      }

      log(`report=failed taskId="${taskId}" result="${result}"`);
      return false;

    } catch (error) {
      log(`report=error taskId="${taskId}" error="${(error as Error).message}"`);
      return false;
    }
  }

  /**
   * Utility method for delays
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Export singleton instance
export const captchaSolver = new CaptchaSolver();

// Helper functions for common use cases
export async function solveRecaptcha(sitekey: string, pageUrl: string, options: Partial<RecaptchaV2Options> = {}): Promise<CaptchaResult> {
  return captchaSolver.solveRecaptchaV2({
    sitekey,
    pageUrl,
    ...options
  });
}

export async function solveImageCaptcha(imageBase64: string, options: Partial<NormalCaptchaOptions> = {}): Promise<CaptchaResult> {
  return captchaSolver.solveNormalCaptcha({
    imageBase64,
    ...options
  });
}

export async function getCaptchaBalance(): Promise<number> {
  return captchaSolver.getBalance();
}

export function isCaptchaSolverEnabled(): boolean {
  return captchaSolver.isEnabled();
}