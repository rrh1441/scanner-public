import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  env: {
    SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    SCANNER_API_URL: process.env.SCANNER_API_URL,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  },
  async rewrites() {
    return [
      {
        source: '/api/scanner/:path*',
        destination: `${process.env.SCANNER_API_URL || 'http://localhost:8000'}/api/:path*`
      }
    ];
  }
};

export default nextConfig;
