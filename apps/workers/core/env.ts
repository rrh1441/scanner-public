/**
 * Environment configuration and guards for the security scanning pipeline
 */

export const GG_MAX_WORKERS = parseInt(process.env.GG_MAX_WORKERS || '4', 10);

// Other environment guards
export const TRUFFLEHOG_GIT_DEPTH = parseInt(process.env.TRUFFLEHOG_GIT_DEPTH || '3', 10);
export const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '2', 10);