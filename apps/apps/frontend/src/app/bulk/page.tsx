'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { scannerAPI } from '@/lib/api-client';
import { normalizeDomain } from '@/lib/utils';
import { ArrowLeft, Plus, Trash2, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import Link from 'next/link';
import { Input } from '@/components/ui/input';
import { useRouter } from 'next/navigation';

interface BulkScanEntry {
  id: string;
  companyName: string;
  domain: string;
  tags: string;
}

export default function BulkScanPage() {
  const router = useRouter();
  const [entries, setEntries] = useState<BulkScanEntry[]>([
    { id: '1', companyName: '', domain: '', tags: '' }
  ]);

  const bulkScan = useMutation({
    mutationFn: async () => {
      const validEntries = entries.filter(e => e.companyName && e.domain);
      
      return scannerAPI.createBulkScans({
        companies: validEntries.map(entry => ({
          companyName: entry.companyName,
          domain: normalizeDomain(entry.domain),
          tags: entry.tags.split(',').map(t => t.trim()).filter(Boolean)
        }))
      });
    },
    onSuccess: () => {
      router.push('/');
    }
  });

  const addEntry = () => {
    setEntries([...entries, {
      id: Date.now().toString(),
      companyName: '',
      domain: '',
      tags: ''
    }]);
  };

  const removeEntry = (id: string) => {
    setEntries(entries.filter(e => e.id !== id));
  };

  const updateEntry = (id: string, field: keyof BulkScanEntry, value: string) => {
    setEntries(entries.map(e => 
      e.id === id ? { ...e, [field]: value } : e
    ));
  };

  const validEntries = entries.filter(e => e.companyName && e.domain);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center gap-4">
            <Link href="/">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="h-4 w-4" />
              </Button>
            </Link>
            <h1 className="text-xl font-bold">Bulk Security Scan</h1>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-4xl">
        <Card>
          <CardHeader>
            <CardTitle>Add Multiple Scans</CardTitle>
            <CardDescription>
              Add multiple companies to scan at once. Each scan will run independently.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {entries.map((entry) => (
                <div key={entry.id} className="grid gap-4 md:grid-cols-4 p-4 border rounded-lg">
                  <div>
                    <label className="text-sm font-medium">Company Name</label>
                    <Input
                      placeholder="Example Corp"
                      value={entry.companyName}
                      onChange={(e) => updateEntry(entry.id, 'companyName', e.target.value)}
                      disabled={bulkScan.isPending}
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Domain</label>
                    <Input
                      placeholder="example.com"
                      value={entry.domain}
                      onChange={(e) => updateEntry(entry.id, 'domain', e.target.value)}
                      disabled={bulkScan.isPending}
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Tags</label>
                    <Input
                      placeholder="tag1, tag2"
                      value={entry.tags}
                      onChange={(e) => updateEntry(entry.id, 'tags', e.target.value)}
                      disabled={bulkScan.isPending}
                    />
                  </div>
                  <div className="flex items-end">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeEntry(entry.id)}
                      disabled={entries.length === 1 || bulkScan.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}

              <Button
                variant="outline"
                onClick={addEntry}
                disabled={bulkScan.isPending}
                className="w-full"
              >
                <Plus className="mr-2 h-4 w-4" />
                Add Another Company
              </Button>

              {bulkScan.isError && (
                <div className="flex items-center gap-2 text-sm text-destructive">
                  <AlertCircle className="h-4 w-4" />
                  <span>{bulkScan.error?.message || 'Failed to create scans'}</span>
                </div>
              )}

              {bulkScan.data && (
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-2 mb-4">
                      <CheckCircle className="h-5 w-5 text-green-500" />
                      <h3 className="font-medium">Scan Results</h3>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span>Successful scans:</span>
                        <Badge variant="secondary">{bulkScan.data.scans.length}</Badge>
                      </div>
                      {bulkScan.data.errors.length > 0 && (
                        <div className="flex items-center justify-between text-sm">
                          <span>Failed scans:</span>
                          <Badge variant="destructive">{bulkScan.data.errors.length}</Badge>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              <div className="flex items-center justify-between pt-4">
                <p className="text-sm text-muted-foreground">
                  {validEntries.length} {validEntries.length === 1 ? 'scan' : 'scans'} ready
                </p>
                <Button
                  onClick={() => bulkScan.mutate()}
                  disabled={validEntries.length === 0 || bulkScan.isPending}
                >
                  {bulkScan.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating Scans...
                    </>
                  ) : (
                    `Start ${validEntries.length} ${validEntries.length === 1 ? 'Scan' : 'Scans'}`
                  )}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}