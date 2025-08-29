'use client';

import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { scannerAPI } from '@/lib/api-client';
import { formatDate, getSeverityColor, getStatusColor } from '@/lib/utils';
import { ArrowLeft, RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function ScanDetailsPage() {
  const params = useParams();
  const scanId = params.id as string;

  const { data: scan, isLoading: scanLoading, error: scanError, refetch: refetchScan } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scannerAPI.getScanStatus(scanId),
    refetchInterval: (query) => {
      if (query.state.data?.status === 'processing' || query.state.data?.status === 'queued') {
        return 5000;
      }
      return false;
    },
  });

  const { data: findings, isLoading: findingsLoading, refetch: refetchFindings } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => scannerAPI.getScanFindings(scanId),
    enabled: scan?.status === 'completed',
  });

  if (scanLoading) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <div className="container mx-auto">
          <Card>
            <CardContent className="py-12 text-center">
              <RefreshCw className="mx-auto h-8 w-8 animate-spin text-muted-foreground" />
              <p className="mt-4 text-muted-foreground">Loading scan details...</p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <div className="container mx-auto">
          <Card>
            <CardContent className="py-12 text-center">
              <AlertTriangle className="mx-auto h-12 w-12 text-destructive mb-4" />
              <h3 className="text-lg font-medium mb-2">Scan not found</h3>
              <p className="text-muted-foreground mb-4">
                The scan you&apos;re looking for doesn&apos;t exist or has been removed.
              </p>
              <Link href="/">
                <Button>
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Back to Dashboard
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const severityCounts = findings?.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>) || {};

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/">
                <Button variant="ghost" size="sm">
                  <ArrowLeft className="h-4 w-4" />
                </Button>
              </Link>
              <div>
                <h1 className="text-xl font-bold">{scan.company_name}</h1>
                <p className="text-sm text-muted-foreground">{scan.domain}</p>
              </div>
            </div>
            <Badge className={getStatusColor(scan.status)}>
              {scan.status === 'processing' && <RefreshCw className="mr-1 h-3 w-3 animate-spin" />}
              {scan.status}
            </Badge>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid gap-6 lg:grid-cols-4">
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Scan Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Scan ID</p>
                  <p className="text-sm font-mono">{scan.scan_id}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Created</p>
                  <p className="text-sm">{formatDate(scan.created_at)}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Updated</p>
                  <p className="text-sm">{formatDate(scan.updated_at)}</p>
                </div>
                {scan.tags && scan.tags.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-muted-foreground mb-2">Tags</p>
                    <div className="flex flex-wrap gap-1">
                      {scan.tags.map(tag => (
                        <Badge key={tag} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="pt-4 space-y-2">
                  <Button 
                    variant="outline" 
                    className="w-full justify-start"
                    onClick={() => {
                      refetchScan();
                      refetchFindings();
                    }}
                  >
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Refresh
                  </Button>
                </div>
              </CardContent>
            </Card>

            {scan.status === 'completed' && findings && findings.length > 0 && (
              <Card className="mt-6">
                <CardHeader>
                  <CardTitle className="text-base">Findings Summary</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(severityCounts).map(([severity, count]) => (
                      <div key={severity} className="flex items-center justify-between">
                        <span className={`text-sm font-medium ${getSeverityColor(severity).split(' ')[0]}`}>
                          {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </span>
                        <Badge variant="secondary">{count}</Badge>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 pt-4 border-t">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Total Findings</span>
                      <span className="text-lg font-bold">{findings.length}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          <div className="lg:col-span-3">
            {scan.status === 'processing' || scan.status === 'queued' ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <RefreshCw className="mx-auto h-12 w-12 animate-spin text-primary mb-4" />
                  <h3 className="text-lg font-medium mb-2">Scan in Progress</h3>
                  <p className="text-muted-foreground">
                    This scan is currently being processed. Results will appear here when complete.
                  </p>
                </CardContent>
              </Card>
            ) : scan.status === 'failed' ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <AlertTriangle className="mx-auto h-12 w-12 text-destructive mb-4" />
                  <h3 className="text-lg font-medium mb-2">Scan Failed</h3>
                  <p className="text-muted-foreground">
                    This scan encountered an error and could not be completed.
                  </p>
                </CardContent>
              </Card>
            ) : scan.status === 'completed' && (!findings || findings.length === 0) ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <CheckCircle className="mx-auto h-12 w-12 text-green-500 mb-4" />
                  <h3 className="text-lg font-medium mb-2">No Findings</h3>
                  <p className="text-muted-foreground">
                    Great news! No security issues were detected for this domain.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-4">
                <h2 className="text-xl font-semibold">Security Findings</h2>
                {findingsLoading ? (
                  <Card>
                    <CardContent className="py-8 text-center">
                      <RefreshCw className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                      <p className="mt-2 text-sm text-muted-foreground">Loading findings...</p>
                    </CardContent>
                  </Card>
                ) : (
                  findings?.map((finding) => (
                    <Card key={finding.id}>
                      <CardHeader>
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <CardTitle className="text-base">{finding.title}</CardTitle>
                            <p className="text-sm text-muted-foreground">{finding.type}</p>
                          </div>
                          <Badge className={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div>
                          <h4 className="text-sm font-medium mb-2">Description</h4>
                          <p className="text-sm text-muted-foreground">{finding.description}</p>
                        </div>
                        {finding.remediation && (
                          <div>
                            <h4 className="text-sm font-medium mb-2">Remediation</h4>
                            <p className="text-sm text-muted-foreground">{finding.remediation}</p>
                          </div>
                        )}
                        {finding.evidence && (
                          <div>
                            <h4 className="text-sm font-medium mb-2">Evidence</h4>
                            <pre className="text-xs bg-muted p-3 rounded-md overflow-x-auto">
                              {JSON.stringify(finding.evidence, null, 2)}
                            </pre>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}