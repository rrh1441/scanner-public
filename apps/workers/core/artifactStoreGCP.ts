import { Firestore } from '@google-cloud/firestore';

const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT || 'precise-victory-467219-s4';

const firestore = new Firestore({
  projectId: PROJECT_ID
});

console.log(`[artifactStoreGCP] Initialized Firestore with project: ${PROJECT_ID}`);

// Recursively sanitize undefined values to prevent Firestore errors
function deepSanitizeUndefined(obj: any): any {
  if (obj === null || obj === undefined) {
    return null;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => deepSanitizeUndefined(item));
  }
  
  if (typeof obj === 'object' && obj !== null) {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = deepSanitizeUndefined(value);
    }
    return sanitized;
  }
  
  return obj;
}

// Export a stub pool for backward compatibility
// This is no longer used in GCP implementation
export const pool = {
  query: async () => ({ rows: [] }),
  connect: async () => ({ release: () => {} }),
  end: async () => {}
};

export interface ArtifactInput {
  type: string;
  val_text: string;
  severity: string;
  src_url?: string;
  sha256?: string;
  mime?: string;
  meta?: any;
  description?: string;
  repro_command?: string;
}

// Insert artifact into Firestore
// Function overloads for backward compatibility
export function insertArtifact(artifact: ArtifactInput): Promise<number>;
export function insertArtifact(
  type: string,
  val_text: string,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta?: any
): Promise<number>;
export function insertArtifact(
  type: string,
  val_text: string,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta: any,
  unused?: any
): Promise<number>;
export async function insertArtifact(
  artifactOrType: ArtifactInput | string,
  val_text?: string,
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta?: any,
  unused?: any
): Promise<number> {
  // Handle legacy 4 or 5 parameter calls
  if (typeof artifactOrType === 'string') {
    const artifact: ArtifactInput = {
      type: artifactOrType,
      val_text: val_text || '',
      severity: severity || 'INFO',
      meta: meta || {}
    };
    return insertArtifactInternal(artifact);
  }
  
  // Handle new single-parameter calls
  return insertArtifactInternal(artifactOrType as ArtifactInput);
}

async function insertArtifactInternal(artifact: ArtifactInput): Promise<number> {
  try {
    // Recursively sanitize undefined values to null for Firestore compatibility
    const sanitizedArtifact: any = deepSanitizeUndefined({ ...artifact });
    
    console.log('[Firestore] Inserting artifact:', {
      type: sanitizedArtifact.type,
      severity: sanitizedArtifact.severity,
      scan_id: artifact.meta?.scan_id || 'unknown'
    });
    
    const docRef = await firestore.collection('artifacts').add({
      ...sanitizedArtifact,
      created_at: new Date().toISOString(),
      scan_id: artifact.meta?.scan_id || 'unknown'
    });
    
    console.log(`[Firestore] Successfully inserted artifact: ${docRef.id}`);
    
    // Return a fake ID for compatibility
    return Date.now();
  } catch (error: any) {
    console.error('[Firestore] Failed to insert artifact:', {
      error: error.message,
      code: error.code,
      details: error.details,
      artifact_type: artifact?.type
    });
    // Don't throw - log and continue to prevent scan failure
    return -1;
  }
}

// Stub for compatibility
export async function initializeDatabase(): Promise<void> {
  console.log('Using Firestore - no initialization needed');
}

// Insert finding into Firestore
// Function overloads for insertFinding backward compatibility
export function insertFinding(finding: any): Promise<number>;
export function insertFinding(
  artifactId: number,
  findingType: string,
  recommendation: string,
  description?: string,
  reproCommand?: string
): Promise<number>;
export async function insertFinding(
  findingOrArtifactId: any | number,
  findingType?: string,
  recommendation?: string,
  description?: string,
  reproCommand?: string
): Promise<number> {
  // Handle legacy 4 or 5 parameter calls
  if (typeof findingOrArtifactId === 'number' && findingType) {
    // Fetch the artifact to get scan_id and other metadata
    let artifactScanId = null;
    let artifactSeverity = 'MEDIUM'; // default
    
    try {
      const artifactDoc = await firestore.collection('artifacts').doc(findingOrArtifactId.toString()).get();
      if (artifactDoc.exists) {
        const artifactData = artifactDoc.data();
        artifactScanId = artifactData?.meta?.scan_id || artifactData?.scan_id;
        artifactSeverity = artifactData?.severity || 'MEDIUM';
      }
    } catch (error) {
      console.error('[Firestore] Failed to fetch artifact for finding:', error);
    }
    
    const finding = {
      artifact_id: findingOrArtifactId,
      finding_type: findingType,
      recommendation: recommendation || '',
      description: description || '',
      repro_command: reproCommand || null,
      scan_id: artifactScanId, // Inherit from artifact
      severity: artifactSeverity,
      type: findingType
    };
    return insertFindingInternal(finding);
  }
  
  // Handle new single-parameter calls
  return insertFindingInternal(findingOrArtifactId);
}

async function insertFindingInternal(finding: any): Promise<number> {
  try {
    // Recursively sanitize undefined values to null for Firestore compatibility
    const sanitizedFinding: any = deepSanitizeUndefined({ ...finding });
    
    console.log('[Firestore] Inserting finding:', {
      type: sanitizedFinding.type,
      severity: sanitizedFinding.severity,
      scan_id: sanitizedFinding.scan_id
    });
    
    const docRef = await firestore.collection('findings').add({
      ...sanitizedFinding,
      created_at: new Date().toISOString()
    });
    
    console.log(`[Firestore] Successfully inserted finding: ${docRef.id}`);
    
    // Return a fake ID for compatibility
    return Date.now();
  } catch (error: any) {
    console.error('[Firestore] Failed to insert finding:', {
      error: error.message,
      code: error.code,
      details: error.details,
      finding_type: finding?.type
    });
    // Don't throw - log and continue to prevent scan failure
    return -1;
  }
}

