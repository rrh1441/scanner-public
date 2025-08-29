/**
 * Adversarial Media Scan Module
 * 
 * Performs reputational risk detection by searching for adverse media coverage
 * about target companies using Serper.dev's search API.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';

// Configuration constants
const SERPER_ENDPOINT = 'https://google.serper.dev/search';
const WINDOW_DAYS = 730; // 24 months lookback
const API_TIMEOUT_MS = 15_000;
const MAX_RESULTS_PER_QUERY = 20;
const MAX_FINDINGS_PER_CATEGORY = 5;
const QUERY_DELAY_MS = 1000; // Between queries

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[adversarialMediaScan]', ...args);

interface SerperSearchResult {
  title: string;
  link: string;
  snippet: string;
  date?: string;
  source?: string;
}

interface CategorizedArticle extends SerperSearchResult {
  category: string;
  relevanceScore: number;
}

interface AdversarialMediaSummary {
  totalArticles: number;
  categoryCount: number;
  categorizedResults: Record<string, CategorizedArticle[]>;
  scanDurationMs: number;
  queriesSuccessful: number;
  queriesTotal: number;
}

/**
 * Generate targeted search queries for comprehensive adverse media coverage
 */
function generateSearchQueries(company: string, domain: string): string[] {
  return [
    `"${company}" (lawsuit OR "legal action" OR fine OR settlement OR sued)`,
    `"${domain}" (breach OR hack OR "data breach" OR "security incident" OR ransomware)`,
    `"${company}" (bankruptcy OR layoffs OR "financial distress" OR recall OR scandal)`,
    `"${company}" CEO OR founder (fraud OR misconduct OR harassment OR arrested)`
  ];
}

/**
 * Check if article is within the configured time window
 */
function isRecentArticle(dateStr: string | undefined, windowDays: number): boolean {
  if (!dateStr) return true; // Include if no date info
  
  try {
    const articleDate = new Date(dateStr).getTime();
    const cutoffDate = Date.now() - (windowDays * 24 * 60 * 60 * 1000);
    
    return articleDate > cutoffDate;
  } catch {
    return true; // Include if date parsing fails
  }
}

/**
 * Classify article into risk categories based on content analysis
 */
function classifyArticle(title: string, snippet: string): string {
  const text = (title + ' ' + snippet).toLowerCase();
  
  // Clear conditional logic for each category
  if (/lawsuit|litigation|regulator|fine|settlement|sued|court|judgment|penalty/.test(text)) {
    return 'Litigation / Regulatory';
  }
  
  if (/breach|hack|data breach|security incident|ransomware|cyber|leaked|exposed/.test(text)) {
    return 'Data Breach / Cyber Incident';
  }
  
  if (/fraud|misconduct|harassment|arrested|criminal|embezzlement|bribery/.test(text)) {
    return 'Executive Misconduct';
  }
  
  if (/bankruptcy|layoffs|financial distress|default|debt|insolvency|closure/.test(text)) {
    return 'Financial Distress';
  }
  
  if (/recall|injury|death|defect|safety|harm|poison|contamination/.test(text)) {
    return 'Product Safety / Customer Harm';
  }
  
  if (/discrimination|environment|pollution|esg|controversy|protest|boycott/.test(text)) {
    return 'Social / Environmental Controversy';
  }
  
  return 'Other'; // Will be filtered out
}

/**
 * Calculate relevance score for article based on title/snippet content
 */
function calculateRelevanceScore(article: SerperSearchResult, company: string): number {
  const text = (article.title + ' ' + article.snippet).toLowerCase();
  const companyLower = company.toLowerCase();
  
  let score = 0;
  
  // Company name mentions
  const companyMentions = (text.match(new RegExp(companyLower, 'g')) || []).length;
  score += companyMentions * 2;
  
  // Recency boost
  if (article.date) {
    const articleDate = new Date(article.date).getTime();
    const daysSince = (Date.now() - articleDate) / (24 * 60 * 60 * 1000);
    if (daysSince < 30) score += 3;
    else if (daysSince < 90) score += 2;
    else if (daysSince < 365) score += 1;
  }
  
  // Source credibility boost (simplified)
  if (article.source) {
    const credibleSources = ['reuters', 'bloomberg', 'wsj', 'ft.com', 'ap.org', 'bbc'];
    if (credibleSources.some(source => article.source!.toLowerCase().includes(source))) {
      score += 2;
    }
  }
  
  return score;
}

/**
 * Remove duplicate articles by URL across all queries
 */
function deduplicateArticles(articles: SerperSearchResult[]): SerperSearchResult[] {
  const seen = new Set<string>();
  return articles.filter(article => {
    if (seen.has(article.link)) return false;
    seen.add(article.link);
    return true;
  });
}

/**
 * Execute search query against Serper API
 */
async function executeSearchQuery(query: string, apiKey: string): Promise<SerperSearchResult[]> {
  try {
    log(`Executing search query: "${query.substring(0, 50)}..."`);
    
    const response = await httpClient.post(SERPER_ENDPOINT, {
      q: query,
      num: MAX_RESULTS_PER_QUERY,
      tbm: 'nws', // News search
      tbs: `qdr:y2` // Last 2 years to match our window
    }, {
      headers: {
        'X-API-KEY': apiKey,
        'Content-Type': 'application/json'
      },
      timeout: API_TIMEOUT_MS
    });
    
    const results: SerperSearchResult[] = (response.data.organic || []).map((item: any) => ({
      title: item.title || '',
      link: item.link || '',
      snippet: item.snippet || '',
      date: item.date,
      source: item.source
    }));
    
    log(`Query returned ${results.length} results`);
    return results;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Search query failed: ${errorMsg}`);
    
    // Return empty array to continue with other queries
    return [];
  }
}

/**
 * Process and categorize search results
 */
function processSearchResults(
  results: SerperSearchResult[], 
  company: string
): Record<string, CategorizedArticle[]> {
  
  // Filter by time window
  const recentArticles = results.filter(article => 
    isRecentArticle(article.date, WINDOW_DAYS)
  );
  
  log(`Filtered to ${recentArticles.length} recent articles (within ${WINDOW_DAYS} days)`);
  
  // Categorize and score articles
  const categorized: Record<string, CategorizedArticle[]> = {};
  
  recentArticles.forEach(article => {
    const category = classifyArticle(article.title, article.snippet);
    
    // Skip 'Other' category
    if (category === 'Other') return;
    
    const relevanceScore = calculateRelevanceScore(article, company);
    
    if (!categorized[category]) {
      categorized[category] = [];
    }
    
    categorized[category].push({
      ...article,
      category,
      relevanceScore
    });
  });
  
  // Sort each category by relevance score
  Object.keys(categorized).forEach(category => {
    categorized[category].sort((a, b) => b.relevanceScore - a.relevanceScore);
  });
  
  return categorized;
}

/**
 * Main scan function
 */
export async function runAdversarialMediaScan(job: { 
  company: string; 
  domain: string; 
  scanId: string 
}): Promise<number> {
  const { company, domain, scanId } = job;
  const startTime = Date.now();
  
  log(`Starting adversarial media scan for company="${company}" domain="${domain}"`);
  
  // Validate inputs
  if (!company || !domain) {
    log('Missing required parameters: company and domain');
    return 0;
  }
  
  // Check API key
  const apiKey = process.env.SERPER_KEY;
  if (!apiKey) {
    log('SERPER_KEY not configured, emitting error and exiting');
    
    await insertArtifact({
      type: 'scan_error',
      val_text: 'Adversarial media scan failed: SERPER_KEY not configured',
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        reason: 'missing_api_key'
      }
    });
    
    return 0;
  }
  
  try {
    // Generate search queries
    const searchQueries = generateSearchQueries(company, domain);
    log(`Generated ${searchQueries.length} search queries`);
    
    let allResults: SerperSearchResult[] = [];
    let successfulQueries = 0;
    
    // Execute each query with delay
    for (let i = 0; i < searchQueries.length; i++) {
      const query = searchQueries[i];
      
      const results = await executeSearchQuery(query, apiKey);
      if (results.length > 0) {
        allResults = allResults.concat(results);
        successfulQueries++;
      }
      
      // Add delay between queries (except for the last one)
      if (i < searchQueries.length - 1) {
        await new Promise(resolve => setTimeout(resolve, QUERY_DELAY_MS));
      }
    }
    
    // Deduplicate results
    const uniqueResults = deduplicateArticles(allResults);
    log(`Collected ${uniqueResults.length} unique articles (${allResults.length - uniqueResults.length} duplicates removed)`);
    
    // Process and categorize results
    const categorizedResults = processSearchResults(uniqueResults, company);
    const totalArticles = Object.values(categorizedResults).reduce((sum, articles) => sum + articles.length, 0);
    const categoryCount = Object.keys(categorizedResults).length;
    
    log(`Categorized ${totalArticles} articles into ${categoryCount} risk categories`);
    
    // Create summary artifact
    const summary: AdversarialMediaSummary = {
      totalArticles,
      categoryCount,
      categorizedResults,
      scanDurationMs: Date.now() - startTime,
      queriesSuccessful: successfulQueries,
      queriesTotal: searchQueries.length
    };
    
    const artifactId = await insertArtifact({
      type: 'adverse_media_summary',
      val_text: `Found ${totalArticles} adverse media articles across ${categoryCount} risk categories`,
      severity: totalArticles > 10 ? 'HIGH' : totalArticles > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        total_articles: totalArticles,
        categories: categorizedResults,
        scan_duration_ms: summary.scanDurationMs,
        queries_successful: successfulQueries,
        queries_total: searchQueries.length
      }
    });
    
    // Generate findings for top articles in each category
    let findingsCount = 0;
    for (const [category, articles] of Object.entries(categorizedResults)) {
      const topArticles = articles
        .sort((a, b) => new Date(b.date || '1970-01-01').getTime() - new Date(a.date || '1970-01-01').getTime())
        .slice(0, MAX_FINDINGS_PER_CATEGORY);

      for (const article of topArticles) {
        await insertFinding(
          artifactId,
          'ADVERSE_MEDIA',
          `${category}: ${article.title}`,
          `Source: ${article.source || 'Unknown'} | Link: ${article.link}`
        );
        findingsCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    log(`Adversarial media scan complete: ${findingsCount} findings generated in ${duration}ms`);
    
    return findingsCount;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Adversarial media scan failed: ${errorMsg}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Adversarial media scan failed: ${errorMsg}`,
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        error: true,
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
}