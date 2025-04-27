"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

interface Summary {
  total_scans: number;
  detection_rate: number;
  total_malware: number;
  total_clean: number;
}

interface MimeType {
  _id: string;
  count: number;
  malicious_count: number;
}

interface Scan {
  _id: string;
  filename?: string;
  scan_date?: string;
  ml_prediction: string | { prediction: string };
}

interface DailyTrend {
  date: string;
  total_scans: number;
  clean_files: number;
  malicious_files: number;
}

interface Feature {
  feature: string;
  average_importance: number;
  description: string;
  occurrence_count: number;
}

interface DashboardData {
  summary: Summary;
  mime_distribution: MimeType[];
  recent_scans: Scan[];
  top_features: Feature[];
  daily_trends: DailyTrend[];
}



import {
  Shield,
  AlertTriangle,
  FileCheck,
  Activity,
  ChevronDown,
  FileType,
  Clock,
  Search,
  Loader2
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";

export default function DashboardPage() {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isFeatureOpen, setIsFeatureOpen] = useState(true);
  const [isRecentOpen, setIsRecentOpen] = useState(true);
  const [isTrendOpen, setIsTrendOpen] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/dashboard`
        );
        if (!response.ok) throw new Error('Failed to fetch dashboard data');
        const data = await response.json();
        setDashboardData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 300000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="flex flex-col items-center gap-2">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading dashboard data...</p>
      </div>
    </div>
  );
  
  if (error) return (
    <div className="flex items-center justify-center min-h-screen">
      <Card className="w-[400px]">
        <CardHeader>
          <CardTitle className="text-destructive">Error</CardTitle>
          <CardDescription>Failed to load dashboard data</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{error}</p>
          <Button 
            className="mt-4 w-full" 
            onClick={() => window.location.reload()}
          >
            Try Again
          </Button>
        </CardContent>
      </Card>
    </div>
  );

  if (!dashboardData) return null;

  const { summary, mime_distribution, recent_scans, top_features, daily_trends } = dashboardData;

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of malware analysis and detection statistics
        </p>
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summary.total_scans}</div>
            <p className="text-xs text-muted-foreground mt-1">
              All-time scan count
            </p>
          </CardContent>
        </Card>

        <Card className="hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Detection Rate</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summary.detection_rate.toFixed(1)}%
            </div>
            <Progress 
              value={summary.detection_rate} 
              className="mt-2"
            />
          </CardContent>
        </Card>

        <Card className="hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Malware Detected</CardTitle>
            <Shield className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{summary.total_malware}</div>
            <Progress 
              value={(summary.total_malware / summary.total_scans) * 100} 
              className="mt-2"
              indicatorClassName="bg-destructive"
            />
          </CardContent>
        </Card>

        <Card className="hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Clean Files</CardTitle>
            <FileCheck className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{summary.total_clean}</div>
            <Progress 
              value={(summary.total_clean / summary.total_scans) * 100} 
              className="mt-2"
              indicatorClassName="bg-green-500"
            />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* File Types Section */}
        <Card>
          <Collapsible open={isFeatureOpen} onOpenChange={setIsFeatureOpen}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle>File Types</CardTitle>
                <CardDescription>Distribution of analyzed file types</CardDescription>
              </div>
              <CollapsibleTrigger asChild>
                <Button variant="ghost" size="sm">
                  <ChevronDown className={`h-4 w-4 transition-transform ${isFeatureOpen ? "transform rotate-180" : ""}`} />
                </Button>
              </CollapsibleTrigger>
            </CardHeader>
            <CollapsibleContent>
              <CardContent>
                <ScrollArea className="h-[300px] pr-4">
                  {mime_distribution.map((type, index) => (
                    <div key={index} className="mb-4">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-sm font-medium">{type._id || "Unknown"}</span>
                        <span className="text-sm text-muted-foreground">
                          {type.count} files
                        </span>
                      </div>
                      <div className="flex gap-2">
                        <Progress 
                          value={(type.count / summary.total_scans) * 100} 
                          className="h-2"
                        />
                        <Badge variant="outline" className="w-16 justify-center">
                          {((type.count / summary.total_scans) * 100).toFixed(1)}%
                        </Badge>
                      </div>
                      {type.malicious_count > 0 && (
                        <p className="text-xs text-destructive mt-1">
                          {type.malicious_count} malicious files detected
                        </p>
                      )}
                    </div>
                  ))}
                </ScrollArea>
              </CardContent>
            </CollapsibleContent>
          </Collapsible>
        </Card>

        {/* Recent Scans Section */}
        <Card>
          <Collapsible open={isRecentOpen} onOpenChange={setIsRecentOpen}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle>Recent Scans</CardTitle>
                <CardDescription>Latest file analysis results</CardDescription>
              </div>
              <CollapsibleTrigger asChild>
                <Button variant="ghost" size="sm">
                  <ChevronDown className={`h-4 w-4 transition-transform ${isRecentOpen ? "transform rotate-180" : ""}`} />
                </Button>
              </CollapsibleTrigger>
            </CardHeader>
            <CollapsibleContent>
              <CardContent>
                <ScrollArea className="h-[300px]">
                  <div className="space-y-4">
                    {recent_scans.map((scan) => (
                      <div key={scan._id} className="flex items-center space-x-4">
                        <div className="flex-1 space-y-1">
                          <p className="text-sm font-medium leading-none">
                            {typeof scan.filename === 'string' ? scan.filename : 'Unnamed File'}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'No date'}
                          </p>
                        </div>
                        <Badge variant={scan.ml_prediction === "Malware" ? "destructive" : "secondary"}>
                          {typeof scan.ml_prediction === 'string' ? scan.ml_prediction : 
                           (scan.ml_prediction && typeof scan.ml_prediction.prediction === 'string') ? 
                             scan.ml_prediction.prediction : 'Unknown'}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </CollapsibleContent>
          </Collapsible>
        </Card>

        {/* Top Features Section */}
        <Card className="lg:col-span-2">
          <Collapsible open={isTrendOpen} onOpenChange={setIsTrendOpen}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle>Key Malware Indicators</CardTitle>
                <CardDescription>Most significant features in malware detection</CardDescription>
              </div>
              <CollapsibleTrigger asChild>
                <Button variant="ghost" size="sm">
                  <ChevronDown className={`h-4 w-4 transition-transform ${isTrendOpen ? "transform rotate-180" : ""}`} />
                </Button>
              </CollapsibleTrigger>
            </CardHeader>
            <CollapsibleContent>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {top_features.map((feature, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{feature.feature}</span>
                        <Badge variant="outline">
                          {(feature.average_importance * 100).toFixed(1)}%
                        </Badge>
                      </div>
                      <Progress 
                        value={feature.average_importance * 100} 
                        className="h-2"
                      />
                      <p className="text-sm text-muted-foreground">
                        {feature.description}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Observed in {feature.occurrence_count} samples
                      </p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </CollapsibleContent>
          </Collapsible>
        </Card>

        {/* Daily Trends Section */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Daily Analysis Trends</CardTitle>
            <CardDescription>Scan activity and detection rates over time</CardDescription>
          </CardHeader>
          <CardContent>
            {daily_trends && (
              <div className="space-y-4">
                {daily_trends.map((day, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="font-medium">{day.date ? new Date(day.date).toLocaleDateString() : 'Unknown date'}</span>
                      <Badge variant="outline">
                        {day.total_scans} scans
                      </Badge>
                    </div>
                    <div className="flex justify-between text-sm text-muted-foreground">
                      <span>Clean: {day.clean_files}</span>
                      <span>Malicious: {day.malicious_files}</span>
                      <span>Detection Rate: {((day.malicious_files / day.total_scans) * 100).toFixed(1)}%</span>
                    </div>
                    <Progress 
                      value={(day.malicious_files / day.total_scans) * 100} 
                      className="h-2"
                    />
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}