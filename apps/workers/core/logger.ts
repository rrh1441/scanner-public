export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3
}

const LOG_LEVEL = process.env.LOG_LEVEL === 'DEBUG' ? LogLevel.DEBUG : LogLevel.INFO;

// Structured logging interface
interface LogContext {
  module?: string;
  scanId?: string;
  domain?: string;
  action?: string;
  duration?: number;
  error?: Error;
  [key: string]: any;
}

function formatMessage(level: string, message: string, context?: LogContext): string {
  const timestamp = new Date().toISOString();
  let logLine = `[${timestamp}] [${level}]`;
  
  if (context?.module) {
    logLine += ` [${context.module}]`;
  }
  
  if (context?.scanId) {
    logLine += ` [scan:${context.scanId}]`;
  }
  
  if (context?.domain) {
    logLine += ` [${context.domain}]`;
  }
  
  logLine += ` ${message}`;
  
  if (context?.duration !== undefined) {
    logLine += ` (${context.duration}ms)`;
  }
  
  return logLine;
}

export function log(message: string, context?: LogContext) {
  console.log(formatMessage('INFO', message, context));
}

export function debug(message: string, context?: LogContext) {
  if (LOG_LEVEL <= LogLevel.DEBUG) {
    console.log(formatMessage('DEBUG', message, context));
  }
}

export function info(message: string, context?: LogContext) {
  if (LOG_LEVEL <= LogLevel.INFO) {
    console.log(formatMessage('INFO', message, context));
  }
}

export function warn(message: string, context?: LogContext) {
  if (LOG_LEVEL <= LogLevel.WARN) {
    console.warn(formatMessage('WARN', message, context));
  }
}

export function error(message: string, context?: LogContext) {
  console.error(formatMessage('ERROR', message, context));
  
  if (context?.error) {
    console.error(context.error.stack || context.error.message);
  }
}

// Legacy support - keep old interface for gradual migration
export function logLegacy(...args: any[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}]`, ...args);
} 