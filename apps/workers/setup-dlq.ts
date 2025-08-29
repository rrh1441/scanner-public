#!/usr/bin/env tsx
/**
 * Script to set up Dead Letter Queue (DLQ) for scan-jobs subscription
 * This ensures failed messages are not lost and can be analyzed
 */

import { PubSub } from '@google-cloud/pubsub';

const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT || 'precise-victory-467219-s4';
const MAIN_TOPIC = 'scan-jobs';
const MAIN_SUBSCRIPTION = 'scan-jobs-subscription';
const DLQ_TOPIC = 'scan-jobs-dlq';
const DLQ_SUBSCRIPTION = 'scan-jobs-dlq-subscription';
const MAX_DELIVERY_ATTEMPTS = 5;

async function setupDeadLetterQueue() {
  const pubsub = new PubSub({ projectId: PROJECT_ID });
  
  console.log(`Setting up Dead Letter Queue for project: ${PROJECT_ID}`);
  
  try {
    // 1. Create DLQ topic
    const [dlqTopicExists] = await pubsub.topic(DLQ_TOPIC).exists();
    if (!dlqTopicExists) {
      await pubsub.createTopic(DLQ_TOPIC);
      console.log(`✅ Created DLQ topic: ${DLQ_TOPIC}`);
    } else {
      console.log(`✓ DLQ topic already exists: ${DLQ_TOPIC}`);
    }
    
    // 2. Create DLQ subscription for monitoring
    const dlqTopic = pubsub.topic(DLQ_TOPIC);
    const [dlqSubExists] = await dlqTopic.subscription(DLQ_SUBSCRIPTION).exists();
    if (!dlqSubExists) {
      await dlqTopic.createSubscription(DLQ_SUBSCRIPTION, {
        ackDeadlineSeconds: 600,
        messageRetentionDuration: {
          seconds: 7 * 24 * 60 * 60, // 7 days
        },
      });
      console.log(`✅ Created DLQ subscription: ${DLQ_SUBSCRIPTION}`);
    } else {
      console.log(`✓ DLQ subscription already exists: ${DLQ_SUBSCRIPTION}`);
    }
    
    // 3. Update main subscription with DLQ policy
    const subscription = pubsub.subscription(MAIN_SUBSCRIPTION);
    const [metadata] = await subscription.getMetadata();
    
    // Configure dead letter policy
    metadata.deadLetterPolicy = {
      deadLetterTopic: dlqTopic.name,
      maxDeliveryAttempts: MAX_DELIVERY_ATTEMPTS,
    };
    
    // Also ensure proper ack deadline
    metadata.ackDeadlineSeconds = 600; // 10 minutes
    
    await subscription.setMetadata(metadata as any);
    console.log(`✅ Updated ${MAIN_SUBSCRIPTION} with DLQ policy`);
    console.log(`   - Dead letter topic: ${DLQ_TOPIC}`);
    console.log(`   - Max delivery attempts: ${MAX_DELIVERY_ATTEMPTS}`);
    console.log(`   - Ack deadline: 600 seconds`);
    
    // 4. Grant necessary permissions
    const [iam] = await dlqTopic.iam.getPolicy();
    const publisherRole = 'roles/pubsub.publisher';
    const serviceAccount = `serviceAccount:service-${PROJECT_ID.split('-')[2]}@gcp-sa-pubsub.iam.gserviceaccount.com`;
    
    const binding = iam.bindings?.find((b: any) => b.role === publisherRole);
    if (!binding?.members?.includes(serviceAccount)) {
      if (!iam.bindings) iam.bindings = [];
      iam.bindings.push({
        role: publisherRole,
        members: [serviceAccount],
      });
      await dlqTopic.iam.setPolicy(iam);
      console.log(`✅ Granted publisher permission to Pub/Sub service account`);
    } else {
      console.log(`✓ Pub/Sub service account already has publisher permission`);
    }
    
    console.log('\n🎉 Dead Letter Queue setup complete!');
    console.log('\nTo monitor failed messages:');
    console.log(`gcloud pubsub subscriptions pull ${DLQ_SUBSCRIPTION} --project=${PROJECT_ID} --limit=10`);
    
  } catch (error) {
    console.error('❌ Error setting up DLQ:', error);
    process.exit(1);
  }
}

// Run the setup
setupDeadLetterQueue();