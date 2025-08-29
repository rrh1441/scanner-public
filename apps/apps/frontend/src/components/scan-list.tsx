'use client';

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { scannerAPI, type Scan } from '@/lib/api-client';
import { formatDate, getStatusColor } from '@/lib/utils';
import { ArrowRight, RefreshCw, Clock } from 'lucide-react';
import Link from 'next/link';

export function ScanList({ scans }: { scans?: Scan[] }) {
  if (!scans || scans.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <p className="text-muted-foreground">No scans found. Create your first scan to get started.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {scans.map((scan) => (
        <ScanItem key={scan.scan_id} scan={scan} />
      ))}
    </div>
  );
}

function ScanItem({ scan }: { scan: Scan }) {
  const { data: updatedScan, refetch } = useQuery({
    queryKey: ['scan', scan.scan_id],
    queryFn: () => scannerAPI.getScanStatus(scan.scan_id),
    initialData: scan,
    refetchInterval: scan.status === 'processing' || scan.status === 'queued' ? 5000 : false,
  });

  const currentScan = updatedScan || scan;
  const isActive = currentScan.status === 'processing' || currentScan.status === 'queued';

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <CardTitle className="text-lg">{currentScan.company_name}</CardTitle>
            <p className="text-sm text-muted-foreground">{currentScan.domain}</p>
          </div>
          <Badge className={getStatusColor(currentScan.status)}>
            {isActive && <RefreshCw className="mr-1 h-3 w-3 animate-spin" />}
            {currentScan.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatDate(currentScan.created_at)}
            </span>
            {currentScan.tags && currentScan.tags.length > 0 && (
              <div className="flex gap-1">
                {currentScan.tags.map(tag => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <div className="flex gap-2">
            {isActive && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => refetch()}
              >
                <RefreshCw className="h-4 w-4" />
              </Button>
            )}
            <Link href={`/scan/${currentScan.scan_id}`}>
              <Button size="sm">
                View Details
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}