export interface DomainValidationResult {
  isValid: boolean;
  normalizedDomain: string;
  originalDomain: string;
  validationErrors: string[];
}

export function normalizeDomain(input: string): DomainValidationResult {
  const originalDomain = input;
  const errors: string[] = [];
  
  // Step 1: Basic sanitization
  let domain = input.trim().toLowerCase();
  
  // Step 2: Remove protocols
  domain = domain.replace(/^https?:\/\//, '');
  
  // Step 3: Remove www prefix
  domain = domain.replace(/^www\./, '');
  
  // Step 4: Remove trailing slashes and paths
  domain = domain.split('/')[0];
  
  // Step 5: Remove port numbers
  domain = domain.split(':')[0];
  
  // Step 6: Validate domain format
  const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
  
  if (!domain) {
    errors.push('Domain cannot be empty');
  } else if (domain.length > 253) {
    errors.push('Domain exceeds maximum length (253 characters)');
  } else if (!domainRegex.test(domain)) {
    errors.push('Invalid domain format');
  } else if (domain.includes('..')) {
    errors.push('Domain contains consecutive dots');
  } else if (domain.startsWith('-') || domain.endsWith('-')) {
    errors.push('Domain cannot start or end with hyphen');
  }
  
  // Step 7: Check for suspicious patterns (but allow for testing)
  const suspiciousPatterns = [
    /^localhost$/i,
    /^127\.0\.0\.1$/,
    /^192\.168\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./
  ];
  
  if (suspiciousPatterns.some(pattern => pattern.test(domain))) {
    errors.push('Private/local domains are not allowed');
  }
  
  return {
    isValid: errors.length === 0,
    normalizedDomain: domain,
    originalDomain,
    validationErrors: errors
  };
}