import { useQueries } from '@tanstack/react-query';
import { scannerAPI } from '@/lib/api-client';

export function useMultipleScans(scanIds: string[]) {
  const results = useQueries({
    queries: scanIds.map(id => ({
      queryKey: ['scan', id],
      queryFn: () => scannerAPI.getScanStatus(id),
    })),
  });

  const scans = results
    .map(result => result.data)
    .filter((scan): scan is NonNullable<typeof scan> => scan !== null && scan !== undefined);

  return scans;
}