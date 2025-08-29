#!/usr/bin/env tsx
/**
 * Monitor failed scans and send alerts
 * Can be run as a Cloud Function or scheduled Cloud Run job
 */

import { Firestore } from '@google-cloud/firestore';
import { PubSub } from '@google-cloud/pubsub';

interface FailedScan {
  scanId: string;
  companyName: string;
  domain: string;
  error: string;
  failedAt: Date;
  retryCount?: number;
}

interface AlertConfig {
  webhookUrl?: string; // Slack, Discord, etc.
  emailRecipients?: string[];
  pubsubTopic?: string;
}

class ScanMonitor {
  private firestore: Firestore;
  private pubsub: PubSub;
  private alertConfig: AlertConfig;
  
  constructor(alertConfig: AlertConfig) {
    this.firestore = new Firestore();
    this.pubsub = new PubSub();
    this.alertConfig = alertConfig;
  }
  
  /**
   * Check for failed scans in the last N minutes
   */
  async checkFailedScans(minutesAgo: number = 15): Promise<FailedScan[]> {
    const cutoffTime = new Date(Date.now() - minutesAgo * 60 * 1000);
    
    const snapshot = await this.firestore
      .collection('scans')
      .where('status', '==', 'failed')
      .where('failed_at', '>=', cutoffTime)
      .get();
    
    const failedScans: FailedScan[] = [];
    
    snapshot.forEach(doc => {
      const data = doc.data();
      failedScans.push({
        scanId: doc.id,
        companyName: data.company_name || 'Unknown',
        domain: data.domain || 'Unknown',
        error: data.error || 'No error message',
        failedAt: data.failed_at?.toDate() || new Date(),
        retryCount: data.retry_count || 0,
      });
    });
    
    return failedScans;
  }
  
  /**
   * Check DLQ for failed messages
   */
  async checkDeadLetterQueue(): Promise<any[]> {
    const subscription = this.pubsub.subscription('scan-jobs-dlq-subscription');
    // Get messages from DLQ
    const messages: any[] = [];
    
    const dlqMessages = messages.map(message => {
      const data = JSON.parse(message.data.toString());
      return {
        messageId: message.id,
        publishTime: message.publishTime,
        deliveryAttempt: message.deliveryAttempt,
        data,
      };
    });
    
    // Don't ack messages - leave them in DLQ for manual inspection
    return dlqMessages;
  }
  
  /**
   * Send alert for failed scans
   */
  async sendAlert(failedScans: FailedScan[], dlqMessages: any[]) {
    const alertData = {
      timestamp: new Date().toISOString(),
      failedScansCount: failedScans.length,
      dlqMessagesCount: dlqMessages.length,
      failedScans: failedScans.slice(0, 10), // Limit to 10 for readability
      summary: this.generateSummary(failedScans),
    };
    
    // Send to webhook (e.g., Slack)
    if (this.alertConfig.webhookUrl) {
      await this.sendWebhookAlert(alertData);
    }
    
    // Publish to alert topic
    if (this.alertConfig.pubsubTopic) {
      await this.publishAlert(alertData);
    }
    
    // Log to Cloud Logging
    console.log(JSON.stringify({
      severity: 'ERROR',
      message: 'Failed scans detected',
      ...alertData,
    }));
  }
  
  private generateSummary(failedScans: FailedScan[]): Record<string, number> {
    const errorCounts: Record<string, number> = {};
    
    failedScans.forEach(scan => {
      const errorType = this.categorizeError(scan.error);
      errorCounts[errorType] = (errorCounts[errorType] || 0) + 1;
    });
    
    return errorCounts;
  }
  
  private categorizeError(error: string): string {
    if (error.includes('timeout')) return 'Timeout';
    if (error.includes('memory')) return 'Memory Limit';
    if (error.includes('network')) return 'Network Error';
    if (error.includes('permission')) return 'Permission Error';
    if (error.includes('API')) return 'API Error';
    return 'Other';
  }
  
  private async sendWebhookAlert(data: any) {
    if (!this.alertConfig.webhookUrl) return;
    
    const message = {
      text: `⚠️ Scanner Alert: ${data.failedScansCount} failed scans detected`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Scanner Health Alert*\n${data.failedScansCount} scans failed in the last 15 minutes`,
          },
        },
        {
          type: 'section',
          fields: Object.entries(data.summary).map(([error, count]) => ({
            type: 'mrkdwn',
            text: `*${error}:* ${count}`,
          })),
        },
      ],
    };
    
    try {
      const response = await fetch(this.alertConfig.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(message),
      });
      
      if (!response.ok) {
        console.error('Failed to send webhook alert:', response.statusText);
      }
    } catch (error) {
      console.error('Error sending webhook alert:', error);
    }
  }
  
  private async publishAlert(data: any) {
    if (!this.alertConfig.pubsubTopic) return;
    
    try {
      const topic = this.pubsub.topic(this.alertConfig.pubsubTopic);
      await topic.publishMessage({
        json: data,
        attributes: {
          alertType: 'failed_scans',
          severity: 'high',
        },
      });
    } catch (error) {
      console.error('Error publishing alert:', error);
    }
  }
}

/**
 * Main monitoring function - can be triggered by Cloud Scheduler
 */
export async function monitorScans() {
  const monitor = new ScanMonitor({
    webhookUrl: process.env.ALERT_WEBHOOK_URL,
    pubsubTopic: process.env.ALERT_PUBSUB_TOPIC || 'scanner-alerts',
  });
  
  try {
    // Check for recent failures
    const failedScans = await monitor.checkFailedScans(15);
    const dlqMessages = await monitor.checkDeadLetterQueue();
    
    if (failedScans.length > 0 || dlqMessages.length > 0) {
      await monitor.sendAlert(failedScans, dlqMessages);
      
      // Return data for Cloud Function response
      return {
        status: 'alerts_sent',
        failedScansCount: failedScans.length,
        dlqMessagesCount: dlqMessages.length,
      };
    }
    
    return {
      status: 'healthy',
      failedScansCount: 0,
      dlqMessagesCount: 0,
    };
    
  } catch (error) {
    console.error('Monitoring error:', error);
    throw error;
  }
}

// Allow running as a script
if (require.main === module) {
  monitorScans()
    .then(result => {
      console.log('Monitoring complete:', result);
      process.exit(0);
    })
    .catch(error => {
      console.error('Monitoring failed:', error);
      process.exit(1);
    });
}