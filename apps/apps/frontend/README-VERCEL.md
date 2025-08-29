# Vercel Deployment Guide

🚀 **Connected to GitHub auto-deployment!**

## Quick Setup

1. **Deploy to Vercel**:
   ```bash
   cd apps/apps/frontend
   npx vercel --prod
   ```

2. **Configure Environment Variables** in Vercel Dashboard:
   - `NEXT_PUBLIC_SCANNER_API_URL=https://scanner-api-242181373909.us-central1.run.app`

3. **Update Backend CORS** (if needed):
   Add your Vercel domain to the CORS origins in `/apps/api-main/server.ts`

## Local Development

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Create `.env.local`**:
   ```bash
   NEXT_PUBLIC_SCANNER_API_URL=https://scanner-api-242181373909.us-central1.run.app
   ```

3. **Run development server**:
   ```bash
   npm run dev
   ```

4. **Test with Vercel CLI**:
   ```bash
   npx vercel dev
   ```

## API Communication

The frontend communicates with the GCP Cloud Run backend via:
- Server-side API routes in `/src/app/api/proxy/[...path]/route.ts`
- Uses Google Auth for backend authentication
- CORS is already configured on the backend for Vercel domains

## Environment Variables

- `NEXT_PUBLIC_SCANNER_API_URL`: Backend API endpoint (required)
- `GOOGLE_APPLICATION_CREDENTIALS`: Service account path (optional, for enhanced auth)

## Deployment Notes

- Remove GCP-specific configurations (already done)
- Vercel handles build and deployment automatically
- No Docker configuration needed
- CORS pre-configured for `*.vercel.app` domains