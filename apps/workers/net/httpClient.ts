import * as dns from 'node:dns';
import { Agent, Dispatcher, request, interceptors } from 'undici';

export type HttpMethod = 'GET' | 'POST' | 'HEAD' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

export interface HttpRequestOptions {
  url: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  body?: string | Buffer | Uint8Array;
  totalTimeoutMs?: number;
  connectTimeoutMs?: number;
  firstByteTimeoutMs?: number;
  idleSocketTimeoutMs?: number;
  forceIPv4?: boolean;
  probeConnectWithHead?: boolean;
  maxBodyBytes?: number;
  maxRedirects?: number;
  disableKeepAlive?: boolean;
}

export interface HttpResponse {
  url: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  body: Uint8Array;
}

const DEFAULTS = {
  totalTimeoutMs: 10_000,
  connectTimeoutMs: 3_000,
  firstByteTimeoutMs: 5_000,
  idleSocketTimeoutMs: 5_000,
  forceIPv4: true,
  probeConnectWithHead: false,
  maxBodyBytes: 2_000_000,
  maxRedirects: 5,
  disableKeepAlive: false,
} as const;

// Create a custom Agent with better timeout control
// IPv4 forcing is handled by NODE_OPTIONS=--dns-result-order=ipv4first
const ipv4Agent = new Agent({
  connect: {
    timeout: DEFAULTS.connectTimeoutMs,
  },
  bodyTimeout: DEFAULTS.idleSocketTimeoutMs,
  headersTimeout: DEFAULTS.firstByteTimeoutMs,
  keepAliveTimeout: 1, // Minimal keep-alive to disable connection reuse
  keepAliveMaxTimeout: 1,
  pipelining: 0, // Disable pipelining
}).compose(interceptors.redirect({ maxRedirections: DEFAULTS.maxRedirects }));

// Standard agent without IPv4 forcing
const standardAgent = new Agent({
  connect: {
    timeout: DEFAULTS.connectTimeoutMs,
  },
  bodyTimeout: DEFAULTS.idleSocketTimeoutMs,
  headersTimeout: DEFAULTS.firstByteTimeoutMs,
  keepAliveTimeout: 5000,
  keepAliveMaxTimeout: 10000,
  pipelining: 0,
}).compose(interceptors.redirect({ maxRedirections: DEFAULTS.maxRedirects }));

function headersToObject(headers: Record<string, string | string[]>): Record<string, string> {
  const obj: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    obj[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  }
  return obj;
}

export async function httpRequest(opts: HttpRequestOptions): Promise<HttpResponse> {
  const {
    url,
    method = 'GET',
    headers = {},
    body,
    totalTimeoutMs = DEFAULTS.totalTimeoutMs,
    connectTimeoutMs = DEFAULTS.connectTimeoutMs,
    firstByteTimeoutMs = DEFAULTS.firstByteTimeoutMs,
    idleSocketTimeoutMs = DEFAULTS.idleSocketTimeoutMs,
    forceIPv4 = DEFAULTS.forceIPv4,
    probeConnectWithHead = DEFAULTS.probeConnectWithHead,
    maxBodyBytes = DEFAULTS.maxBodyBytes,
    maxRedirects = DEFAULTS.maxRedirects,
    disableKeepAlive = DEFAULTS.disableKeepAlive,
  } = opts;

  // Select the appropriate agent based on IPv4 forcing
  const agent = forceIPv4 ? ipv4Agent : standardAgent;

  const requestHeaders: Record<string, string> = { ...headers };
  
  // Disable keep-alive if requested
  if (disableKeepAlive) {
    requestHeaders['Connection'] = 'close';
  }

  // Optional: Probe connection with HEAD request first
  if (probeConnectWithHead && method !== 'HEAD') {
    try {
      await request(url, {
        method: 'HEAD',
        headers: requestHeaders,
        dispatcher: agent,
        bodyTimeout: connectTimeoutMs,
        headersTimeout: connectTimeoutMs,
      });
    } catch (err) {
      // Probe failed but continue with actual request
      console.warn('HEAD probe failed, continuing with actual request');
    }
  }

  // Make the actual request using undici
  const abortController = new AbortController();
  const totalTimer = setTimeout(() => abortController.abort(), totalTimeoutMs);
  
  try {
    const { statusCode, headers: respHeaders, body: respBody } = await request(url, {
      method: method as Dispatcher.HttpMethod,
      headers: requestHeaders,
      body,
      dispatcher: agent,
      signal: abortController.signal,
      bodyTimeout: idleSocketTimeoutMs,
      headersTimeout: firstByteTimeoutMs,
    });

    // Read the body with size limit
    const chunks: Uint8Array[] = [];
    let received = 0;
    
    for await (const chunk of respBody) {
      const data = chunk instanceof Buffer ? new Uint8Array(chunk) : chunk;
      received += data.byteLength;
      
      if (received > maxBodyBytes) {
        respBody.destroy();
        throw new Error(`Body too large (> ${maxBodyBytes} bytes)`);
      }
      
      chunks.push(data);
    }

    // Combine chunks into single buffer
    const bodyData = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      bodyData.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return {
      url,
      status: statusCode,
      ok: statusCode >= 200 && statusCode < 300,
      headers: headersToObject(respHeaders),
      body: bodyData,
    };
  } catch (err: any) {
    if (err.name === 'AbortError' || err.code === 'UND_ERR_ABORTED') {
      throw new Error(`Request timeout after ${totalTimeoutMs}ms`);
    }
    if (err.code === 'UND_ERR_HEADERS_TIMEOUT') {
      throw new Error(`First byte timeout after ${firstByteTimeoutMs}ms`);
    }
    if (err.code === 'UND_ERR_BODY_TIMEOUT') {
      throw new Error(`Body read timeout after ${idleSocketTimeoutMs}ms`);
    }
    if (err.code === 'UND_ERR_CONNECT_TIMEOUT') {
      throw new Error(`Connection timeout after ${connectTimeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(totalTimer);
  }
}

export async function httpGetText(url: string, opt?: Omit<HttpRequestOptions, 'url' | 'method'>): Promise<string> {
  const r = await httpRequest({ url, method: 'GET', ...(opt ?? {}) });
  return new TextDecoder('utf-8').decode(r.body);
}

// Axios error for compatibility
export class AxiosError extends Error {
  code?: string;
  config?: AxiosCompatConfig;
  response?: {
    data: any;
    status: number;
    headers: Record<string, string>;
  };
  
  constructor(message: string, code?: string, config?: AxiosCompatConfig, response?: any) {
    super(message);
    this.name = 'AxiosError';
    this.code = code;
    this.config = config;
    this.response = response;
  }
}

// Axios request config alias for compatibility
export type AxiosRequestConfig = AxiosCompatConfig;

// Axios-compatible wrapper for easier migration
export interface AxiosCompatConfig {
  url?: string;
  method?: HttpMethod;
  headers?: Record<string, string>;
  data?: any;
  params?: Record<string, any>;
  timeout?: number;
  maxContentLength?: number;
  maxBodyLength?: number;
  maxRedirects?: number;
  validateStatus?: (status: number) => boolean;
  responseType?: 'json' | 'text' | 'arraybuffer';
  httpsAgent?: any;
}

export interface AxiosCompatResponse<T = any> {
  data: T;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  config: AxiosCompatConfig;
  request?: any;
}

export async function axiosCompat<T = any>(config: AxiosCompatConfig | string): Promise<AxiosCompatResponse<T>> {
  // Handle string URL
  if (typeof config === 'string') {
    config = { url: config, method: 'GET' };
  }
  
  const {
    url,
    method = 'GET',
    headers = {},
    data,
    params,
    timeout = 10000,
    maxContentLength = 50 * 1024 * 1024, // 50MB default
    maxBodyLength = maxContentLength,
    maxRedirects = 5,
    validateStatus = (status) => status >= 200 && status < 300,
    responseType = 'json',
    httpsAgent // Ignored, we handle TLS internally
  } = config;
  
  if (!url) throw new Error('URL is required');
  
  // Build URL with query params
  let finalUrl = url;
  if (params && Object.keys(params).length > 0) {
    const urlObj = new URL(url);
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        urlObj.searchParams.append(key, String(value));
      }
    });
    finalUrl = urlObj.toString();
  }
  
  // Convert data to appropriate format
  let body: string | Buffer | undefined;
  if (data) {
    if (typeof data === 'string' || data instanceof Buffer) {
      body = data;
    } else {
      body = JSON.stringify(data);
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    }
  }
  
  try {
    const response = await httpRequest({
      url: finalUrl,
      method,
      headers,
      body,
      totalTimeoutMs: timeout,
      maxBodyBytes: Math.min(maxContentLength, maxBodyLength),
      maxRedirects,
      forceIPv4: true
    });
    
    // Check status
    if (!validateStatus(response.status)) {
      const error: any = new Error(`Request failed with status code ${response.status}`);
      error.response = {
        data: response.body,
        status: response.status,
        headers: response.headers
      };
      throw error;
    }
    
    // Parse response data based on responseType
    let responseData: T;
    if (responseType === 'arraybuffer') {
      responseData = response.body as any;
    } else if (responseType === 'text') {
      responseData = new TextDecoder('utf-8').decode(response.body) as any;
    } else {
      // Try to parse as JSON
      const text = new TextDecoder('utf-8').decode(response.body);
      try {
        responseData = text ? JSON.parse(text) : null;
      } catch {
        // If not JSON, return as text
        responseData = text as any;
      }
    }
    
    return {
      data: responseData,
      status: response.status,
      statusText: response.ok ? 'OK' : 'Error',
      headers: response.headers,
      config
    };
  } catch (error: any) {
    // Enhance error for axios compatibility
    if (!error.response) {
      error.config = config;
      error.code = error.code || 'ECONNABORTED';
      error.message = error.message || 'Network Error';
    }
    throw error;
  }
}

// Convenience methods for axios compatibility
export const httpClient = {
  get: <T = any>(url: string, config?: Omit<AxiosCompatConfig, 'url' | 'method'>) => 
    axiosCompat<T>({ ...config, url, method: 'GET' }),
  
  post: <T = any>(url: string, data?: any, config?: Omit<AxiosCompatConfig, 'url' | 'method' | 'data'>) => 
    axiosCompat<T>({ ...config, url, method: 'POST', data }),
  
  put: <T = any>(url: string, data?: any, config?: Omit<AxiosCompatConfig, 'url' | 'method' | 'data'>) => 
    axiosCompat<T>({ ...config, url, method: 'PUT', data }),
  
  delete: <T = any>(url: string, config?: Omit<AxiosCompatConfig, 'url' | 'method'>) => 
    axiosCompat<T>({ ...config, url, method: 'DELETE' }),
  
  patch: <T = any>(url: string, data?: any, config?: Omit<AxiosCompatConfig, 'url' | 'method' | 'data'>) => 
    axiosCompat<T>({ ...config, url, method: 'PATCH', data }),
  
  head: <T = any>(url: string, config?: Omit<AxiosCompatConfig, 'url' | 'method'>) => 
    axiosCompat<T>({ ...config, url, method: 'HEAD' }),
  
  options: <T = any>(url: string, config?: Omit<AxiosCompatConfig, 'url' | 'method'>) => 
    axiosCompat<T>({ ...config, url, method: 'OPTIONS' }),
  
  request: axiosCompat
};