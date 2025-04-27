"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  FileScan, 
  ChevronRight,
  Clock,
  Loader2,
  FileWarning,
  Search
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

export default function ReportsPage() {
  const router = useRouter();
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/scans?page=${page}&per_page=10`);
        
        if (!response.ok) {
          throw new Error(`Failed to fetch reports: ${response.status}`);
        }
        
        const data = await response.json();
        setReports(data.scans);
        setTotalPages(data.pages || 1);
      } catch (error) {
        console.error("Error fetching reports:", error);
        setError(error instanceof Error ? error.message : "An error occurred");
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, [page]);

  // Helper function to check if prediction indicates malware
  const isMalicious = (prediction: any): boolean => {
    if (typeof prediction === 'string') {
      return prediction.toLowerCase().includes("malware");
    }
    return false;
  };

  if (loading && page === 1) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-t-2 border-primary animate-spin"></div>
            <Shield className="absolute inset-0 m-auto w-8 h-8 text-primary/70" />
          </div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading reports...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md p-6 border-destructive/50 bg-destructive/5">
          <div className="flex flex-col items-center gap-4 text-center">
            <AlertTriangle className="h-12 w-12 text-destructive" />
            <h2 className="text-lg font-semibold">Error Loading Reports</h2>
            <p className="text-sm text-muted-foreground">{error}</p>
            <Button 
              onClick={() => router.push('/upload')}
              variant="outline"
              className="mt-2"
            >
              Return to Scanner
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto p-6 space-y-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <FileScan className="h-8 w-8 text-primary" />
              Scan Reports
            </h1>
            <p className="text-muted-foreground mt-1">
              View and analyze all your file scan results
            </p>
          </div>
          
          <Button 
            onClick={() => router.push('/upload')}
            variant="default"
            className="w-full md:w-auto"
          >
            Scan New File
          </Button>
        </div>
        
        {/* Reports List */}
        <div className="space-y-4">
          {reports.length === 0 && !loading ? (
            <Card className="p-6 flex flex-col items-center justify-center text-center">
              <FileWarning className="h-12 w-12 text-muted-foreground/50 mb-4" />
              <h2 className="text-lg font-semibold">No Reports Found</h2>
              <p className="text-sm text-muted-foreground mt-1">
                You haven&apos;t scanned any files yet. Start by scanning a file.
              </p>
              <Button 
                onClick={() => router.push('/upload')}
                variant="outline"
                className="mt-4"
              >
                Go to Scanner
              </Button>
            </Card>
          ) : (
            reports.map((report) => (
              <Card 
                key={report._id}
                className="p-4 bg-card/50 backdrop-blur border border-border/50 hover:bg-card/80 transition-colors cursor-pointer overflow-hidden relative"
                onClick={() => router.push(`/report/${report.file_hash}`)}
              >
                <div className="absolute -right-20 -top-20 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
                
                <div className="relative z-10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start gap-3">
                      {report.status === 'complete' ? (
                        isMalicious(report.ml_prediction) ? (
                          <AlertTriangle className="h-6 w-6 text-destructive flex-shrink-0 mt-1" />
                        ) : (
                          <CheckCircle className="h-6 w-6 text-green-500 flex-shrink-0 mt-1" />
                        )
                      ) : (
                        <Clock className="h-6 w-6 text-muted-foreground flex-shrink-0 mt-1" />
                      )}
                      
                      <div className="flex-1 min-w-0">
                        <h2 className="text-lg font-semibold truncate">{report.filename}</h2>
                        <p className="text-sm text-muted-foreground">
                          {report.scan_date ? format(new Date(report.scan_date), "PPp") : "Unknown date"}
                        </p>
                        
                        <div className="flex flex-wrap items-center gap-2 mt-2">
                          <Badge 
                            variant={
                              report.status === 'complete' 
                                ? report.ml_prediction?.toLowerCase().includes("malware") || 
                                report.ml_prediction?.toLowerCase().includes("malicious")
                                  ? "destructive" 
                                  : "secondary"
                                : "outline"
                            } 
                            className={cn(
                              "text-xs",
                              report.status === 'pending' && "animate-pulse"
                            )}
                          >
                            {report.status === 'complete' 
                              ? report.ml_prediction?.toLowerCase().includes("malware") || 
                              report.ml_prediction?.toLowerCase().includes("malicious")
                              ? "Malicious" 
                              : "Clean"
                              : "Pending"
                            }
                          </Badge>
                          
                          {report.ml_prediction && (
                            <Badge 
                              variant={report.ml_prediction?.toLowerCase().includes("malware") || 
                                report.ml_prediction?.toLowerCase().includes("malicious") ? "destructive" : "outline"} 
                              className={cn(
                                "text-xs",
                                report.ml_prediction?.toLowerCase().includes("malware") || 
                                report.ml_prediction?.toLowerCase().includes("malicious")
                                  ? "bg-destructive/10" 
                                  : "bg-green-500/10 text-green-500 border-green-500/30"
                              )}
                            >
                              ML: {typeof report.ml_prediction === 'string' ? report.ml_prediction : 'Unknown'}
                            </Badge>
                          )}
                        </div>
                        
                        <div className="mt-3 flex items-center">
                          <span className="text-xs font-mono bg-muted/30 px-1.5 py-0.5 rounded truncate max-w-[250px] sm:max-w-[400px]">
                            {report.file_hash}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center self-end sm:self-center">
                    <Button 
                      variant="ghost" 
                      size="icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        router.push(`/report/${report.file_hash}`);
                      }}
                      className="text-muted-foreground hover:text-primary"
                    >
                      <ChevronRight className="h-5 w-5" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))
          )}
          
          {/* Loading more indicator */}
          {loading && page > 1 && (
            <div className="flex justify-center py-4">
              <Loader2 className="h-6 w-6 text-primary animate-spin" />
            </div>
          )}
          
          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 mt-6">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1 || loading}
              >
                Previous
              </Button>
              
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  // Show pages around current page
                  let pageNum = i + 1;
                  if (totalPages > 5) {
                    if (page <= 3) {
                      pageNum = i + 1;
                    } else if (page >= totalPages - 2) {
                      pageNum = totalPages - 4 + i;
                    } else {
                      pageNum = page - 2 + i;
                    }
                  }
                  
                  return (
                    <Button
                      key={i}
                      variant={page === pageNum ? "default" : "outline"}
                      size="sm"
                      className="w-9"
                      onClick={() => setPage(pageNum)}
                      disabled={loading}
                    >
                      {pageNum}
                    </Button>
                  );
                })}
              </div>
              
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || loading}
              >
                Next
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}