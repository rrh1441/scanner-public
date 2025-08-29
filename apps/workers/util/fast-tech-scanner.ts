import axios from 'axios';
import * as cheerio from 'cheerio';
import pLimit from 'p-limit';

export interface DetectionOpts {
  timeout: number;
  userAgent: string;
  forceHtml: boolean;
  maxRetries: number;
}

export interface Technology {
  name: string;
  slug: string;
  category: string;
  confidence: number;
  version?: string;
  evidence: string;
  cpe?: string;
}

export interface DetectionResult {
  url: string;
  technologies: Technology[];
  duration: number;
  error?: string;
}

const HEADER_SIGS = [
  { pattern: /apache\/([0-9.]+)/i, name: 'Apache HTTP Server', category: 'Web servers', header: 'server' },
  { pattern: /nginx\/([0-9.]+)/i, name: 'Nginx', category: 'Web servers', header: 'server' },
  { pattern: /microsoft-iis\/([0-9.]+)/i, name: 'Microsoft IIS', category: 'Web servers', header: 'server' },
  { pattern: /cloudflare/i, name: 'Cloudflare', category: 'CDN', header: 'server' },
  { pattern: /php\/([0-9.]+)/i, name: 'PHP', category: 'Programming languages', header: 'x-powered-by' },
  { pattern: /asp\.net\/([0-9.]+)/i, name: 'ASP.NET', category: 'Web frameworks', header: 'x-powered-by' },
  { pattern: /express\/([0-9.]+)/i, name: 'Express', category: 'Web frameworks', header: 'x-powered-by' },
  { pattern: /.+/, name: 'Cloudflare', category: 'CDN', header: 'cf-ray' },
  { pattern: /.+/, name: 'Vercel', category: 'Hosting', header: 'x-vercel-cache' },
  { pattern: /.+/, name: 'Netlify', category: 'Hosting', header: 'x-netlify-id' },
  { pattern: /.+/, name: 'Amazon CloudFront', category: 'CDN', header: 'x-amz-cf-id' },
  { pattern: /fastly/i, name: 'Fastly', category: 'CDN', header: 'x-served-by' },
  { pattern: /.+/, name: 'ASP.NET', category: 'Web frameworks', header: 'x-aspnet-version' },
  { pattern: /.+/, name: 'Drupal', category: 'CMS', header: 'x-drupal-cache' },
  { pattern: /.+/, name: 'WordPress', category: 'CMS', header: 'x-pingback' },
  { pattern: /.+/, name: 'Shopify', category: 'E-commerce', header: 'x-shopify-stage' },
  { pattern: /.+/, name: 'Magento', category: 'E-commerce', header: 'x-magento-tags' },
];

const COOKIE_SIGS = [
  { name: 'PHPSESSID', tech: 'PHP', category: 'Programming languages' },
  { name: 'ASP.NET_SessionId', tech: 'ASP.NET', category: 'Web frameworks' },
  { name: 'JSESSIONID', tech: 'Java', category: 'Programming languages' },
  { name: 'connect.sid', tech: 'Express', category: 'Web frameworks' },
  { name: 'laravel_session', tech: 'Laravel', category: 'Web frameworks' },
  { name: '_rails_session', tech: 'Ruby on Rails', category: 'Web frameworks' },
  { name: 'django_session', tech: 'Django', category: 'Web frameworks' },
  { name: 'sessionid', tech: 'Django', category: 'Web frameworks' },
  { name: 'CAKEPHP', tech: 'CakePHP', category: 'Web frameworks' },
  { name: 'ci_session', tech: 'CodeIgniter', category: 'Web frameworks' },
];

const HTML_SIGS = [
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']wordpress[^"']*([0-9.]+)?/i, name: 'WordPress', category: 'CMS' },
  { pattern: /wp-content|wp-includes/i, name: 'WordPress', category: 'CMS' },
  { pattern: /Shopify\.theme/i, name: 'Shopify', category: 'E-commerce' },
  { pattern: /magento/i, name: 'Magento', category: 'E-commerce' },
  { pattern: /<script[^>]*src=[^>]*angular[^>]*>/i, name: 'Angular', category: 'JavaScript frameworks' },
  { pattern: /<script[^>]*src=[^>]*react[^>]*>/i, name: 'React', category: 'JavaScript libraries' },
  { pattern: /<script[^>]*src=[^>]*vue[^>]*>/i, name: 'Vue.js', category: 'JavaScript frameworks' },
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']drupal[^"']*([0-9.]+)?/i, name: 'Drupal', category: 'CMS' },
  { pattern: /<link[^>]*href=[^>]*\/sites\/all\/themes\//i, name: 'Drupal', category: 'CMS' },
  { pattern: /<script[^>]*src=[^>]*jquery[^>]*>/i, name: 'jQuery', category: 'JavaScript libraries' },
  { pattern: /__NEXT_DATA__/i, name: 'Next.js', category: 'Web frameworks' },
  { pattern: /__nuxt/i, name: 'Nuxt.js', category: 'Web frameworks' },
  { pattern: /gatsby/i, name: 'Gatsby', category: 'Static site generators' },
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']joomla[^"']*([0-9.]+)?/i, name: 'Joomla', category: 'CMS' },
];

const DEFAULT_OPTS: DetectionOpts = {
  timeout: 4500,
  userAgent: 'Mozilla/5.0 (compatible; FastTechScanner/1.0)',
  forceHtml: false,
  maxRetries: 1,
};

function generateSlug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

async function detectFromHeaders(url: string, opts: DetectionOpts): Promise<Technology[]> {
  const technologies: Technology[] = [];
  
  try {
    const response = await axios.head(url, {
      timeout: opts.timeout * 0.6,
      validateStatus: () => true,
      headers: { 'User-Agent': opts.userAgent },
      maxRedirects: 3,
    });

    const headers = response.headers;

    for (const sig of HEADER_SIGS) {
      const headerValue = headers[sig.header];
      if (!headerValue) continue;

      const match = headerValue.match(sig.pattern);
      if (match) {
        const version = match[1] || undefined;
        const confidence = version ? 1.0 : 0.9;
        
        technologies.push({
          name: sig.name,
          slug: generateSlug(sig.name),
          category: sig.category,
          confidence,
          version,
          evidence: `${sig.header}: ${headerValue}`,
        });
      }
    }

    return technologies;
  } catch {
    return [];
  }
}

async function detectFromCookies(url: string, opts: DetectionOpts): Promise<Technology[]> {
  const technologies: Technology[] = [];
  
  try {
    const response = await axios.get(url, {
      timeout: opts.timeout * 0.6,
      validateStatus: () => true,
      headers: { 'User-Agent': opts.userAgent },
      maxRedirects: 3,
      maxContentLength: 1024,
    });

    const cookies = response.headers['set-cookie'] || [];
    const cookieString = cookies.join('; ');

    for (const sig of COOKIE_SIGS) {
      if (cookieString.includes(sig.name)) {
        technologies.push({
          name: sig.tech,
          slug: generateSlug(sig.tech),
          category: sig.category,
          confidence: 0.85,
          evidence: `cookie: ${sig.name}`,
        });
      }
    }

    return technologies;
  } catch {
    return [];
  }
}

async function detectFromHtml(url: string, opts: DetectionOpts): Promise<Technology[]> {
  const technologies: Technology[] = [];
  
  try {
    const response = await axios.get(url, {
      timeout: opts.timeout,
      validateStatus: () => true,
      headers: { 'User-Agent': opts.userAgent },
      maxRedirects: 3,
      maxContentLength: 100000,
    });

    if (!response.data || typeof response.data !== 'string') {
      return [];
    }

    const $ = cheerio.load(response.data);
    const html = response.data.toLowerCase();

    for (const sig of HTML_SIGS) {
      const match = html.match(sig.pattern);
      if (match) {
        const version = match[1] || undefined;
        const confidence = version ? 0.95 : 0.8;
        
        technologies.push({
          name: sig.name,
          slug: generateSlug(sig.name),
          category: sig.category,
          confidence,
          version,
          evidence: `html: ${sig.pattern.source}`,
        });
      }
    }

    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
      technologies.push({
        name: generator,
        slug: generateSlug(generator),
        category: 'CMS',
        confidence: 0.9,
        evidence: `meta[name="generator"]: ${generator}`,
      });
    }

    return technologies;
  } catch {
    return [];
  }
}

function deduplicateTechnologies(technologies: Technology[]): Technology[] {
  const seen = new Map<string, Technology>();
  
  for (const tech of technologies) {
    const key = tech.slug;
    const existing = seen.get(key);
    
    if (!existing || tech.confidence > existing.confidence) {
      seen.set(key, tech);
    }
  }
  
  return Array.from(seen.values());
}

export async function detectTechnologies(
  url: string, 
  opts: Partial<DetectionOpts> = {}
): Promise<DetectionResult> {
  const startTime = Date.now();
  const options = { ...DEFAULT_OPTS, ...opts };
  let allTechnologies: Technology[] = [];
  let error: string | undefined;

  try {
    const headerTechs = await detectFromHeaders(url, options);
    allTechnologies.push(...headerTechs);

    const cookieTechs = await detectFromCookies(url, options);
    allTechnologies.push(...cookieTechs);

    if (allTechnologies.length === 0 || options.forceHtml) {
      const htmlTechs = await detectFromHtml(url, options);
      allTechnologies.push(...htmlTechs);
    }

  } catch (err) {
    error = err instanceof Error ? err.message : 'Unknown error';
  }

  const technologies = deduplicateTechnologies(allTechnologies);
  const duration = Date.now() - startTime;

  return {
    url,
    technologies,
    duration,
    error,
  };
}

export async function detectTechnologiesBatch(
  urls: string[],
  opts: Partial<DetectionOpts & { concurrency: number }> = {}
): Promise<DetectionResult[]> {
  if (urls.length === 0) {
    return [];
  }

  const { concurrency = 10, ...detectionOpts } = opts;
  const limit = pLimit(concurrency);

  const promises = urls.map(url =>
    limit(() => detectTechnologies(url, detectionOpts))
  );

  const results = await Promise.allSettled(promises);
  
  return results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      return {
        url: urls[index],
        technologies: [],
        duration: 0,
        error: result.reason?.message || 'Promise rejected',
      };
    }
  });
}