import { NextResponse } from 'next/server';

// Simple health check that doesn't require backend authentication
export async function GET() {
  try {
    // Just return a simple health status without calling the backend
    return NextResponse.json({
      status: 'healthy',
      frontend: 'operational',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return NextResponse.json(
      { 
        status: 'unhealthy', 
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}