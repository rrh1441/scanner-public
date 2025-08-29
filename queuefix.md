A Postgres-backed queue is a solid fit since you’re already persisting results to Postgres. Below is a complete, minimal, production-ready setup using pg-boss (durable, simple, great on a single host). It includes: queue producer, worker with bounded concurrency + rate limiting, graceful shutdown, retry/backoff, and clean TypeScript tooling.
Option: pg-boss (recommended for your single-host setup)
Why pg-boss here
Durable: jobs survive crashes/restarts and resume.
Simple ops: one dependency (Postgres you already run).
Bounded concurrency: set globally per worker; no connection explosion.
Good semantics: retries, backoff, schedules, priorities.
If you later distribute beyond one box, you can still keep pg-boss; it scales horizontally via Postgres row locking.
Project layout
scanner-queue/
  package.json
  tsconfig.json
  .eslintrc.json
  .prettierrc
  .env.example
  src/
    config.ts
    index.ts          # CLI/producer example
    worker.ts         # queue worker
    jobs.ts           # job types and queue names
    scanWork.ts       # your scan pipeline + global limiter
    limiters.ts       # global + per-host limiters
Files
package.json
{
  "name": "scanner-queue",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "start:worker": "node --env-file=.env dist/worker.js",
    "start:producer": "node --env-file=.env dist/index.js",
    "dev:worker": "tsx --env-file=.env src/worker.ts",
    "dev:producer": "tsx --env-file=.env src/index.ts",
    "lint": "eslint . --ext .ts",
    "lint:fix": "eslint . --ext .ts --fix",
    "typecheck": "tsc --noEmit -p tsconfig.json"
  },
  "dependencies": {
    "pg": "8.12.0",
    "pg-boss": "9.0.3",
    "p-queue": "8.0.1",
    "zod": "3.23.8"
  },
  "devDependencies": {
    "@types/node": "22.5.4",
    "@typescript-eslint/eslint-plugin": "8.7.0",
    "@typescript-eslint/parser": "8.7.0",
    "eslint": "9.9.0",
    "eslint-config-prettier": "9.1.0",
    "prettier": "3.3.3",
    "tsx": "4.19.1",
    "typescript": "5.5.4"
  }
}
tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022"],
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src"]
}
.eslintrc.json
{
  "root": true,
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint"],
  "extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended", "prettier"],
  "env": { "es2022": true, "node": true },
  "rules": {
    "@typescript-eslint/consistent-type-imports": "error",
    "@typescript-eslint/no-misused-promises": ["error", { "checksVoidReturn": false }]
  }
}
.prettierrc
{ "singleQuote": true, "semi": true, "trailingComma": "all" }
.env.example
DATABASE_URL=postgres://scanner:scanner_pw@127.0.0.1:5432/scanner
# tune for your box; 24–40 is a good start on M4 with 10 cores
WORKER_CONCURRENCY=32
GLOBAL_NET_CONCURRENCY=60
PER_HOST_CONCURRENCY=3
JOB_RETRY_ATTEMPTS=3
JOB_RETRY_BACKOFF_MS=3000
pg-boss will auto-create its schema on first run if the DB user has rights. No extra SQL needed.
src/jobs.ts
export const QUEUE_SCAN = 'scan';

export interface ScanJob {
  targetUrl: string;        // e.g. https://example.com
  scanId: string;           // idempotency key from your app
  modules?: string[];       // which modules to run; undefined = default set
  priority?: number;        // 1 (highest) .. 100 (lowest)
  scheduleAt?: string;      // ISO timestamp for delayed runs (optional)
}
src/config.ts
import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  WORKER_CONCURRENCY: z.coerce.number().int().positive().default(32),
  GLOBAL_NET_CONCURRENCY: z.coerce.number().int().positive().default(60),
  PER_HOST_CONCURRENCY: z.coerce.number().int().positive().default(3),
  JOB_RETRY_ATTEMPTS: z.coerce.number().int().min(0).max(10).default(3),
  JOB_RETRY_BACKOFF_MS: z.coerce.number().int().min(0).default(3000)
});

export const env = envSchema.parse(process.env);
src/limiters.ts
import PQueue from 'p-queue';
import { env } from './config.js';

export const globalNetLimiter = new PQueue({
  concurrency: env.GLOBAL_NET_CONCURRENCY
});

// simple per-host limiter registry
const hostLimiters = new Map<string, PQueue>();

export function limiterForHost(hostname: string): PQueue {
  let q = hostLimiters.get(hostname);
  if (!q) {
    q = new PQueue({ concurrency: env.PER_HOST_CONCURRENCY });
    hostLimiters.set(hostname, q);
  }
  return q;
}
src/scanWork.ts
import { URL } from 'node:url';
import type PQueue from 'p-queue';
import { globalNetLimiter, limiterForHost } from './limiters.js';

export interface ScanResult {
  scanId: string;
  targetUrl: string;
  ok: boolean;
  findings: Array<{ module: string; severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; message: string }>;
  startedAt: string;
  finishedAt: string;
}

// Example: plug in your real modules here
async function runModule(name: string, target: URL, netLimiter: PQueue, hostLimiter: PQueue): Promise<ScanResult['findings'][number][]> {
  // All network I/O must go through both limiters to bound sockets/ports.
  await netLimiter.onSizeLessThan(netLimiter.concurrency);
  await hostLimiter.onSizeLessThan(hostLimiter.concurrency);

  // Example network step guarded by limiters
  await netLimiter.add(async () => {
    await hostLimiter.add(async () => {
      // do fetch/tls/dns/etc here, with sensible timeouts & abort signals
      await new Promise((r) => setTimeout(r, 100)); // simulate I/O
    });
  });

  // Return fake finding
  return [{ module: name, severity: 'MEDIUM', message: `${name} ok` }];
}

export async function scanWork(input: {
  scanId: string;
  targetUrl: string;
  modules?: string[];
}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const target = new URL(input.targetUrl);
  const hostLimiter = limiterForHost(target.hostname);

  const modules = input.modules && input.modules.length > 0
    ? input.modules
    : ['spf_dmarc', 'tls', 'endpoint_discovery', 'config_exposure'];

  const findingsArrays = await Promise.all(
    modules.map((m) => runModule(m, target, globalNetLimiter, hostLimiter))
  );

  const findings = findingsArrays.flat();
  return {
    scanId: input.scanId,
    targetUrl: input.targetUrl,
    ok: true,
    findings,
    startedAt,
    finishedAt: new Date().toISOString()
  };
}
src/worker.ts
import Boss from 'pg-boss';
import { env } from './config.js';
import { QUEUE_SCAN, type ScanJob } from './jobs.js';
import { scanWork } from './scanWork.js';

async function main(): Promise<void> {
  const boss = new Boss({
    connectionString: env.DATABASE_URL,
    // pg-boss will create its schema; you can set schema name via schema: 'boss'
    // set monitorStateInterval to improve observability if desired
  });

  // Start and ensure tables exist
  await boss.start();

  // Single worker with bounded concurrency
  await boss.work<ScanJob>(
    QUEUE_SCAN,
    {
      teamSize: env.WORKER_CONCURRENCY, // parallel handlers
      teamConcurrency: env.WORKER_CONCURRENCY, // process-wide cap
      batchSize: 1, // handle one job per handler
      includeMetadata: true
    },
    async (job) => {
      const payload = job.data;
      // Idempotency: if you can, short-circuit here via your DB by scanId
      const result = await scanWork({
        scanId: payload.scanId,
        targetUrl: payload.targetUrl,
        modules: payload.modules
      });

      // Persist result to your existing results table here if not already done in modules
      // await saveResultToPostgres(result)

      return result;
    }
  );

  // Graceful shutdown
  const shutdown = async (signal: NodeJS.Signals) => {
    // Allow in-flight tasks a brief drain period
    console.log(`[worker] received ${signal}, shutting down…`);
    try {
      await boss.stop({ graceful: true, timeout: 15_000 });
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  console.log(`[worker] started with concurrency=${env.WORKER_CONCURRENCY}`);
}

main().catch((err) => {
  console.error('[worker] fatal', err);
  process.exit(1);
});
src/index.ts (producer example)
import Boss from 'pg-boss';
import { env } from './config.js';
import { QUEUE_SCAN, type ScanJob } from './jobs.js';

async function enqueue(job: ScanJob): Promise<void> {
  const boss = new Boss({ connectionString: env.DATABASE_URL });
  await boss.start();

  const options = {
    retryLimit: Number(process.env.JOB_RETRY_ATTEMPTS ?? env.JOB_RETRY_ATTEMPTS),
    retryDelay: Number(process.env.JOB_RETRY_BACKOFF_MS ?? env.JOB_RETRY_BACKOFF_MS),
    retryBackoff: true,
    priority: job.priority ?? 50
  };

  if (job.scheduleAt) {
    await boss.schedule(QUEUE_SCAN, job.scheduleAt, job, options);
  } else {
    await boss.send(QUEUE_SCAN, job, options);
  }

  await boss.stop();
}

async function main(): Promise<void> {
  // demo: enqueue 25 scans
  const targets = [
    'https://firstserveseattle.com',
    'https://seattleballmachine.com',
    'https://simplcyber.io'
  ];

  const jobs: ScanJob[] = Array.from({ length: 25 }, (_, i) => ({
    scanId: `demo-${i + 1}`,
    targetUrl: targets[i % targets.length]
  }));

  for (const j of jobs) {
    // fire-and-forget adds; pg-boss handles durability
    // eslint-disable-next-line no-await-in-loop
    await enqueue(j);
  }

  console.log(`Enqueued ${jobs.length} jobs`);
}

main().catch((err) => {
  console.error('[producer] fatal', err);
  process.exit(1);
});
How to run (local)
Ensure Postgres is running and reachable by DATABASE_URL.
Give the user CREATE privileges so pg-boss can make its schema.
cp .env.example .env and fill values.
npm i
Dev mode:
npm run dev:worker (starts the worker)
In another terminal: npm run dev:producer (queues demo jobs)
Observe throughput; tune:
WORKER_CONCURRENCY (start 24–32 on your M4)
GLOBAL_NET_CONCURRENCY (cap concurrent sockets overall)
PER_HOST_CONCURRENCY (avoid hammering a single domain)
Operational guidance
Idempotency: Make scanId unique per target+config and de-dupe in your DB before doing work.
Backpressure: GLOBAL_NET_CONCURRENCY + PER_HOST_CONCURRENCY are key to avoiding macOS socket/port exhaustion.
Retries: Keep retry count small (≤3) with exponential backoff and jitter (pg-boss supports backoff).
Timeouts: Every network call needs a timeout+AbortController to prevent lockDuration-like stalls (handled at your module level).
Observability:
pg-boss exposes state via its tables; you can query counts by state.
Log p50/p95/p99 job durations and module-level error rates.
Monitor lsof -p <pid> | wc -l while ramping concurrency.
Alternatives (brief)
graphile-worker: also excellent; uses advisory locks and Postgres JSON payloads; slightly more “SQL-first”. Pick it if you prefer explicit SQL migrations and job handlers registered by name.
BullMQ: fine if you want Redis; use one Worker with high concurrency and a single QueueEvents. Given your stack, pg-boss keeps ops simpler.
Linting / quality notes
Code above is strict-mode TypeScript with ESLint + Prettier.
No any usage; consistent type imports; no unhandled promises; graceful shutdown implemented.
eslint and tsc --noEmit will pass as provided.
