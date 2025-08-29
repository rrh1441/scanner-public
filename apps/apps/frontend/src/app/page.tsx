'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ScanForm } from '@/components/scan-form';
import { ScanList } from '@/components/scan-list';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { scannerAPI } from '@/lib/api-client';
import { Shield, FileText, Upload } from 'lucide-react';
import Link from 'next/link';
import { useMultipleScans } from '@/hooks/use-multiple-queries';

export default function DashboardPage() {
  const [recentScans, setRecentScans] = useState<string[]>([]);

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: () => scannerAPI.checkHealth(),
    refetchInterval: 30000, // Check every 30 seconds
  });

  const handleScanCreated = (scanId: string) => {
    setRecentScans(prev => [scanId, ...prev].slice(0, 10));
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary" />
              <h1 className="text-2xl font-bold">Dealbrief Security Scanner</h1>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                <div className={`h-2 w-2 rounded-full ${health?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-muted-foreground">
                  {health?.status === 'healthy' ? 'System Operational' : 'System Issues'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          <div className="lg:col-span-1">
            <ScanForm onScanCreated={handleScanCreated} />
            
            <div className="mt-6 space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Quick Actions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Link href="/bulk" className="block">
                    <Button variant="outline" className="w-full justify-start">
                      <FileText className="mr-2 h-4 w-4" />
                      Bulk Scan
                    </Button>
                  </Link>
                  <Link href="/upload" className="block">
                    <Button variant="outline" className="w-full justify-start">
                      <Upload className="mr-2 h-4 w-4" />
                      Upload CSV
                    </Button>
                  </Link>
                </CardContent>
              </Card>
            </div>
          </div>

          <div className="lg:col-span-2">
            <div className="mb-6">
              <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
              {recentScans.length > 0 ? (
                <RecentScansList scanIds={recentScans} />
              ) : (
                <Card>
                  <CardContent className="py-12 text-center">
                    <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                    <h3 className="text-lg font-medium mb-2">No recent scans</h3>
                    <p className="text-muted-foreground">
                      Start a new scan to see results here
                    </p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function RecentScansList({ scanIds }: { scanIds: string[] }) {
  const scans = useMultipleScans(scanIds);
  return <ScanList scans={scans} />;
}