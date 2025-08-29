import { NextRequest, NextResponse } from 'next/server';
import { GoogleAuth } from 'google-auth-library';

const API_BASE = process.env.NEXT_PUBLIC_SCANNER_API_URL || 'https://scanner-api-242181373909.us-central1.run.app';

let auth: GoogleAuth | null = null;

async function getAccessToken(): Promise<string> {
  if (!auth) {
    auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform']
    });
  }
  
  const client = await auth.getClient();
  const accessTokenResponse = await client.getAccessToken();
  
  if (!accessTokenResponse.token) {
    throw new Error('Failed to get access token');
  }
  
  return accessTokenResponse.token;
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  const params = await context.params;
  try {
    const path = params.path.join('/');
    const token = await getAccessToken();
    
    const response = await fetch(`${API_BASE}/${path}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    
    const data = await response.text();
    
    return new NextResponse(data, {
      status: response.status,
      headers: {
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
      },
    });
  } catch (error) {
    console.error('Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  const params = await context.params;
  try {
    const path = params.path.join('/');
    const token = await getAccessToken();
    const body = await request.text();
    
    const response = await fetch(`${API_BASE}/${path}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': request.headers.get('Content-Type') || 'application/json',
      },
      body: body,
    });
    
    const data = await response.text();
    
    return new NextResponse(data, {
      status: response.status,
      headers: {
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
      },
    });
  } catch (error) {
    console.error('Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}