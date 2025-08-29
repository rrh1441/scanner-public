import { Storage } from '@google-cloud/storage';
import fs from 'fs/promises';
import path from 'path';
import { logLegacy as log } from './logger.js';

// Initialize Cloud Storage client
const storage = new Storage();
const BUCKET_NAME = process.env.GCS_BUCKET_NAME || 'dealbrief-scanner-artifacts';

/**
 * Upload a file to Google Cloud Storage
 * @param localPath Local file path to upload
 * @param key Object key/name
 * @param mimeType MIME type of the file
 * @returns Public URL or signed URL of the uploaded file
 */
export async function uploadFile(localPath: string, key: string, mimeType: string): Promise<string> {
  try {
    const bucket = storage.bucket(BUCKET_NAME);
    const file = bucket.file(key);
    
    // Upload file with metadata
    await bucket.upload(localPath, {
      destination: key,
      metadata: {
        contentType: mimeType,
        metadata: {
          'uploaded-by': 'dealbrief-scanner',
          'upload-timestamp': new Date().toISOString(),
        },
      },
    });
    
    // Make the file publicly accessible (optional - remove if you want private files)
    // await file.makePublic();
    
    // Return the GCS URL
    const url = `https://storage.googleapis.com/${BUCKET_NAME}/${key}`;
    
    log(`[objectStore] File uploaded successfully: ${key}`);
    return url;
    
  } catch (error) {
    log(`[objectStore] Failed to upload file ${localPath}:`, (error as Error).message);
    
    // For development/testing, return a placeholder URL if GCS is not configured
    if (!process.env.GOOGLE_APPLICATION_CREDENTIALS && !process.env.GOOGLE_CLOUD_PROJECT) {
      log(`[objectStore] GCS not configured, returning placeholder URL for ${key}`);
      return `placeholder://storage/${key}`;
    }
    
    throw error;
  }
}

/**
 * Generate a signed URL for downloading a file from GCS
 * @param key Object key/name
 * @param expiresIn Expiration time in seconds (default: 1 hour)
 * @returns Signed URL for downloading the file
 */
export async function getDownloadUrl(key: string, expiresIn: number = 3600): Promise<string> {
  try {
    const bucket = storage.bucket(BUCKET_NAME);
    const file = bucket.file(key);
    
    // Generate signed URL
    const [signedUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + expiresIn * 1000,
    });
    
    return signedUrl;
    
  } catch (error) {
    log(`[objectStore] Failed to generate download URL for ${key}:`, (error as Error).message);
    throw error;
  }
}

/**
 * Check if GCS is properly configured
 * @returns boolean indicating if GCS is configured
 */
export function isS3Configured(): boolean {
  // Keep the same function name for compatibility
  return !!(process.env.GOOGLE_APPLICATION_CREDENTIALS || 
           process.env.GOOGLE_CLOUD_PROJECT);
}