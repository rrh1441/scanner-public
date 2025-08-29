'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { scannerAPI } from '@/lib/api-client';
import { normalizeDomain } from '@/lib/utils';
import { AlertCircle, Loader2, Search } from 'lucide-react';

export function ScanForm({ onScanCreated }: { onScanCreated?: (scanId: string) => void }) {
  const [companyName, setCompanyName] = useState('');
  const [domain, setDomain] = useState('');
  const [tags, setTags] = useState('');
  const queryClient = useQueryClient();

  const createScan = useMutation({
    mutationFn: async () => {
      const normalizedDomain = normalizeDomain(domain);
      const tagArray = tags.split(',').map(t => t.trim()).filter(Boolean);
      
      return scannerAPI.createScan({
        companyName,
        domain: normalizedDomain,
        tags: tagArray
      });
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setCompanyName('');
      setDomain('');
      setTags('');
      if (onScanCreated) {
        onScanCreated(data.scan_id || data.scanId!);
      }
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (companyName && domain) {
      createScan.mutate();
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>New Security Scan</CardTitle>
        <CardDescription>
          Enter a company name and domain to start a comprehensive security scan
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="company" className="text-sm font-medium">
              Company Name
            </label>
            <Input
              id="company"
              placeholder="Example Company"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              disabled={createScan.isPending}
              required
            />
          </div>
          
          <div className="space-y-2">
            <label htmlFor="domain" className="text-sm font-medium">
              Domain
            </label>
            <Input
              id="domain"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              disabled={createScan.isPending}
              required
            />
            <p className="text-xs text-muted-foreground">
              Enter domain without http:// or https://
            </p>
          </div>
          
          <div className="space-y-2">
            <label htmlFor="tags" className="text-sm font-medium">
              Tags (optional)
            </label>
            <Input
              id="tags"
              placeholder="tag1, tag2, tag3"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              disabled={createScan.isPending}
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated tags for organizing scans
            </p>
          </div>

          {createScan.isError && (
            <div className="flex items-center gap-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4" />
              <span>{createScan.error?.message || 'Failed to create scan'}</span>
            </div>
          )}

          <Button type="submit" disabled={createScan.isPending} className="w-full">
            {createScan.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Creating Scan...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Start Scan
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}