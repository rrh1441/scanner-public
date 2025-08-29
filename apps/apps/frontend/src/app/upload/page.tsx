'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { scannerAPI } from '@/lib/api-client';
import { ArrowLeft, Upload, FileText, CheckCircle, AlertCircle, Download, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function UploadPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const uploadCSV = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('No file selected');
      return scannerAPI.uploadCSV(file);
    },
    onSuccess: () => {
      setTimeout(() => {
        router.push('/');
      }, 2000);
    }
  });

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.type === 'text/csv' || droppedFile.name.endsWith('.csv')) {
        setFile(droppedFile);
      }
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const downloadTemplate = () => {
    const csv = 'companyName,domain,tags\n"Example Company",example.com,"tag1,tag2"\n"Another Corp",another.com,"client,important"';
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'scan-template.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

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
            <h1 className="text-xl font-bold">CSV Upload</h1>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-2xl">
        <Card>
          <CardHeader>
            <CardTitle>Upload CSV for Bulk Scanning</CardTitle>
            <CardDescription>
              Upload a CSV file with company information to create multiple scans at once
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <h3 className="text-sm font-medium mb-2">CSV Format</h3>
              <div className="bg-muted p-4 rounded-md">
                <p className="text-sm font-mono">companyName,domain,tags</p>
                <p className="text-sm font-mono">{'"Example Company",example.com,"tag1,tag2"'}</p>
                <p className="text-sm font-mono">{'"Another Corp",another.com,"client,important"'}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-2"
                onClick={downloadTemplate}
              >
                <Download className="mr-2 h-4 w-4" />
                Download Template
              </Button>
            </div>

            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                dragActive ? 'border-primary bg-primary/5' : 'border-muted-foreground/25'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <input
                type="file"
                accept=".csv"
                onChange={handleFileInput}
                className="hidden"
                id="csv-upload"
                disabled={uploadCSV.isPending}
              />
              
              {file ? (
                <div className="space-y-4">
                  <FileText className="mx-auto h-12 w-12 text-primary" />
                  <div>
                    <p className="font-medium">{file.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {(file.size / 1024).toFixed(2)} KB
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => setFile(null)}
                    disabled={uploadCSV.isPending}
                  >
                    Remove File
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="mx-auto h-12 w-12 text-muted-foreground" />
                  <div>
                    <label htmlFor="csv-upload" className="cursor-pointer">
                      <span className="text-primary hover:underline">Click to upload</span>
                      <span className="text-muted-foreground"> or drag and drop</span>
                    </label>
                    <p className="text-sm text-muted-foreground mt-1">CSV files only</p>
                  </div>
                </div>
              )}
            </div>

            {uploadCSV.isError && (
              <div className="flex items-center gap-2 text-sm text-destructive">
                <AlertCircle className="h-4 w-4" />
                <span>{uploadCSV.error?.message || 'Upload failed'}</span>
              </div>
            )}

            {uploadCSV.data && (
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 mb-4">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <h3 className="font-medium">Upload Complete</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span>Successful scans:</span>
                      <Badge variant="secondary">{uploadCSV.data.scans.length}</Badge>
                    </div>
                    {uploadCSV.data.errors.length > 0 && (
                      <div className="flex items-center justify-between text-sm">
                        <span>Failed scans:</span>
                        <Badge variant="destructive">{uploadCSV.data.errors.length}</Badge>
                      </div>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground mt-4">
                    Redirecting to dashboard...
                  </p>
                </CardContent>
              </Card>
            )}

            <Button
              className="w-full"
              onClick={() => uploadCSV.mutate()}
              disabled={!file || uploadCSV.isPending || uploadCSV.isSuccess}
            >
              {uploadCSV.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Uploading...
                </>
              ) : (
                <>
                  <Upload className="mr-2 h-4 w-4" />
                  Upload and Start Scans
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}