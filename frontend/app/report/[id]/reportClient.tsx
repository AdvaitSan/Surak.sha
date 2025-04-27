"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  FileScan, 
  ChevronLeft, 
  Clock, 
  FileWarning, 
  Search,
  ArrowUpRight,
  FileIcon,
  BrainCircuit,Info,


  Zap
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { FeatureImportance } from "@/types/types";
export default function ReportClient({ id }: { id: string }) {
  const router = useRouter();
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/report/${id}`);
        
        if (!response.ok) {
          throw new Error(`Failed to fetch report: ${response.status}`);
        }
        
        const data = await response.json();
        console.log("Report data:", data);
        setReport(data);
      } catch (error) {
        console.error("Error fetching report:", error);
        setError(error instanceof Error ? error.message : "An error occurred");
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-t-2 border-primary animate-spin"></div>
            <Shield className="absolute inset-0 m-auto w-8 h-8 text-primary/70" />
          </div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading threat report...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4 empty-20">
        <Card className="max-w-md p-6 border-destructive/50 bg-destructive/5">
          <div className="flex flex-col items-center gap-4 text-center">
            <AlertTriangle className="h-12 w-12 text-destructive" />
            <h2 className="text-lg font-semibold">Error Loading Report</h2>
            <p className="text-sm text-muted-foreground">{error}</p>
            <Button 
              onClick={() => router.push('/upload')}
              variant="outline"
              className="mt-2"
            >
              <ChevronLeft className="mr-2 h-4 w-4" />
              Return to Scanner
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md p-6">
          <div className="flex flex-col items-center gap-4 text-center">
            <FileWarning className="h-12 w-12 text-muted-foreground/50" />
            <h2 className="text-lg font-semibold">Report Not Found</h2>
            <p className="text-sm text-muted-foreground">The requested scan report could not be found.</p>
            <Button 
              onClick={() => router.push('/upload')}
              variant="outline"
              className="mt-2"
            >
              <ChevronLeft className="mr-2 h-4 w-4" />
              Return to Scanner
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  // Determine if the file is malicious based on the report
  const isMalicious = () => {
    if (!report.report?.data?.attributes) return false;
    const stats = report.report.data.attributes.last_analysis_stats;
    return stats && stats.malicious > 0;
  };

  // Get detection ratio
  const getDetectionRatio = () => {
    if (!report.report?.data?.attributes?.last_analysis_stats) return "0/0";
    const stats = report.report.data.attributes.last_analysis_stats;
    const totalEngines = stats.malicious + stats.suspicious + stats.undetected + (stats.harmless || 0);
    return `${stats.malicious}/${totalEngines}`;
  };



  const handleRunDynamicAnalysis = async () => {
    if (!report?.file_hash) return;
    
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/run-dynamic-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ file_hash: report.file_hash, filename: report.filename }),
      });
      
      if (!response.ok) {
        throw new Error(`Failed to start dynamic analysis: ${response.status}`);
      }
      
      // Show some indication that analysis has started
      alert("Dynamic analysis has been initiated. Results will be available once the analysis is complete.");
      
    } catch (error) {
      console.error("Error starting dynamic analysis:", error);
      alert("Failed to start dynamic analysis. Please try again later.");
    }
  };

  // Feature importance component
  const FeatureImportanceCard = ({ featureImportances }: { featureImportances?: FeatureImportance[] }) => {
    if (!featureImportances || featureImportances.length === 0) {
      return null;
    }

    // Get max importance value for scaling
    const maxImportance = Math.max(...featureImportances.map(feature => feature.importance));
    
    return (
      <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
        <h2 className="text-lg font-semibold mb-4 flex items-center">
          <BrainCircuit className="w-5 h-5 mr-2 text-primary" />
          ML Feature Importance
        </h2>
        <p className="text-sm text-muted-foreground mb-4">
          These features had the most significant impact on the machine learning model&apos;s decision.
        </p>
        <div className="space-y-3">
          {featureImportances.map((feature, index) => (
            <div key={index} className="space-y-1">
              <div className="flex justify-between items-center">
                <div className="flex items-center">
                  <span className="text-sm font-medium">{feature.feature}</span>
                  <div title={feature.description}>
                    <Info 
                      className="w-3.5 h-3.5 ml-1.5 text-muted-foreground cursor-help" 
                    />
                  </div>
                </div>
                <span className="text-sm font-mono">{feature.importance.toFixed(4)}</span>
              </div>
              <div className="h-2 bg-muted/20 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary/70"
                  style={{ width: `${(feature.importance / maxImportance) * 100}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </Card>
    );
  };


  const MimeTypeCard = ({ mimeInfo }: { mimeInfo?: any }) => {
    if (!mimeInfo) return null;
    
    return (
      <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
        <h2 className="text-lg font-semibold mb-4 flex items-center">
          <FileIcon className="w-5 h-5 mr-2 text-blue-400" />
          File Information
        </h2>
        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium mb-2">MIME Type</h3>
            <Badge variant="outline" className="text-sm bg-blue-500/10 text-blue-400 border-blue-500/30">
              {mimeInfo.mime_type}
            </Badge>
          </div>
          
          <div>
            <h3 className="text-sm font-medium mb-2">Category</h3>
            <p className="text-sm">{mimeInfo.mime_category}</p>
          </div>
          
          <div>
            <h3 className="text-sm font-medium mb-2">Description</h3>
            <p className="text-sm text-muted-foreground">{mimeInfo.mime_description}</p>
          </div>
        </div>
      </Card>
    );
  };

  // Helper function to safely check if ml_prediction includes a string
  const isMalwarePrediction = (prediction: any) => {
    return typeof prediction === 'string' && (report.ml_prediction?.toLowerCase().includes("malware") || 
    report.ml_prediction?.toLowerCase().includes("malicious"));
  };



  

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto p-6 space-y-8">
        {/* Header with back button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <Button 
            onClick={() => router.push('/upload')}
            variant="ghost"
            className="w-fit"
          >
            <ChevronLeft className="mr-2 h-4 w-4" />
            Back to Scanner
          </Button>
          
          <div className="flex items-center gap-2">
            <Badge variant={isMalicious() ? "destructive" : "secondary"} className="text-xs px-2 py-1">
              {isMalicious() ? `Detected (${getDetectionRatio()})` : "Clean"}
            </Badge>
            
            {report.ml_prediction !== undefined && report.ml_prediction !== null && (
              <Badge 
                variant={isMalwarePrediction(report.ml_prediction) ? "destructive" : "outline"} 
                className={cn(
                  "text-xs px-2 py-1",
                  isMalwarePrediction(report.ml_prediction) 
                    ? "bg-destructive/10" 
                    : "bg-green-500/10 text-green-500 border-green-500/30"
                )}
              >
                ML: {String(report.ml_prediction)}
              </Badge>
            )}
          </div>
        </div>

        {/* Title Section */}
        <div className="space-y-2">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            {isMalicious() ? 
              <AlertTriangle className="h-8 w-8 text-destructive inline animate-pulse" /> : 
              <CheckCircle className="h-8 w-8 text-green-500 inline" />
            }
            Threat Report
          </h1>
          <p className="text-muted-foreground">
            Detailed analysis report for <span className="font-medium">{report.filename}</span>
          </p>
        </div>
        
        {/* File Summary Card */}
        <Card className="p-6 bg-card/50 backdrop-blur border border-border/50 overflow-hidden relative">
          <div className="absolute -right-20 -top-20 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
          <div className="absolute -left-20 -bottom-20 w-64 h-64 bg-secondary/5 rounded-full blur-3xl pointer-events-none"></div>
          
          <div className="relative z-10">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <FileScan className="w-5 h-5 text-primary" />
              File Information
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Basic File Info */}
              <div className="space-y-4">
                <div className="grid grid-cols-[120px_1fr] gap-1">
                  <span className="text-sm text-muted-foreground">Filename:</span>
                  <span className="text-sm font-medium truncate">{report.filename}</span>
                  
                  <span className="text-sm text-muted-foreground">File Hash:</span>
                  <span className="text-sm font-mono text-xs bg-muted/30 px-1.5 py-0.5 rounded  overflow-x-hidden  ">{report.file_hash}</span>
                  
                  <span className="text-sm text-muted-foreground">Scan Date:</span>
                  <span className="text-sm">{report.scan_date ? format(new Date(report.scan_date), "PPpp") : "Unknown"}</span>
                  
                  <span className="text-sm text-muted-foreground">Status:</span>
                  <div>
                    <Badge 
                      variant={isMalicious() ? "destructive" : "secondary"}
                      className={cn(
                        "text-xs",
                        isMalicious() && "animate-pulse"
                      )}
                    >
                      {isMalicious() ? "Malicious" : "Clean"}
                    </Badge>
                  </div>
                </div>
                
                {report.report?.data?.attributes?.type_description && (
                  <div className="bg-muted/20 rounded-md p-3 space-y-2">
                    <h3 className="text-sm font-medium">File Properties</h3>
                    <div className="grid grid-cols-[120px_1fr] gap-1 text-sm">
                      <span className="text-muted-foreground">Type:</span>
                      <span>{report.report.data.attributes.type_description}</span>
                      
                      {report.report.data.attributes.size && (
                        <>
                          <span className="text-muted-foreground">Size:</span>
                          <span>{(report.report.data.attributes.size / 1024).toFixed(2)} KB</span>
                        </>
                      )}
                      
                      {report.report.data.attributes.trid && report.report.data.attributes.trid[0] && (
                        <>
                          <span className="text-muted-foreground">Identified As:</span>
                          <span>{report.report.data.attributes.trid[0].file_type}</span>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
              
              {/* Analysis Results */}
              <div className="space-y-4">
                <div className="flex flex-col space-y-3">
                  {/* ML Detection */}
                  <div className="bg-primary/5 border border-primary/20 rounded-md p-3 flex items-start space-x-3">
                    <Shield className="w-6 h-6 text-primary mt-0.5 flex-shrink-0" />
                    <div>
                      <h3 className="text-sm font-medium flex items-center">
                        Machine Learning Analysis
                        <Zap className="h-3.5 w-3.5 ml-1.5 text-yellow-500" />
                      </h3>
                      <p className="text-sm mt-1">
                        <span className={cn(
                          "font-medium",
                          isMalwarePrediction(report.ml_prediction) ? "text-destructive" : "text-green-500"
                        )}>
                          {report.ml_prediction !== undefined && report.ml_prediction !== null
                            ? String(report.ml_prediction)
                            : "No prediction available"}
                        </span>
                        {report.ml_prediction_time !== undefined && (
                          <span className="text-xs text-muted-foreground ml-2">
                            (analyzed in {report.ml_prediction_time.toFixed(3)}s)
                          </span>
                        )}
                      </p>
                    </div>
                  </div>
                  
                  {/* VirusTotal Detection */}
                  {report.report?.data?.attributes?.last_analysis_stats && (
                    <div className={cn(
                      "border rounded-md p-3 flex items-start space-x-3",
                      isMalicious() 
                        ? "bg-destructive/5 border-destructive/20" 
                        : "bg-green-500/5 border-green-500/20"
                    )}>
                      {isMalicious() ? (
                        <AlertTriangle className="w-6 h-6 text-destructive mt-0.5 flex-shrink-0" />
                      ) : (
                        <CheckCircle className="w-6 h-6 text-green-500 mt-0.5 flex-shrink-0" />
                      )}
                      <div>
                        <h3 className="text-sm font-medium">VirusTotal Analysis</h3>
                        <p className="text-sm mt-1">
                          {isMalicious() ? (
                            <>Detected by <span className="font-medium">{report.report.data.attributes.last_analysis_stats.malicious}</span> security vendors</>
                          ) : (
                            <>Clean file, no detections found</>
                          )}
                        </p>
                        
                        {/* Detection Ratio */}
                        <div className="mt-2 bg-background/50 rounded relative h-2 overflow-hidden">
                          <div 
                            className={cn(
                              "absolute inset-y-0 left-0 transition-all duration-1000",
                              isMalicious() ? "bg-destructive" : "bg-green-500"
                            )}
                            style={{ 
                              width: `${Math.min(100, (report.report.data.attributes.last_analysis_stats.malicious / 
                                (report.report.data.attributes.last_analysis_stats.malicious + 
                                report.report.data.attributes.last_analysis_stats.undetected)) * 100)}%` 
                            }}
                          />
                        </div>
                        
                        {/* Detailed Stats */}
                        <div className="flex gap-3 mt-2 text-xs">
                          <div className="text-destructive">
                            <span className="font-medium">{report.report.data.attributes.last_analysis_stats.malicious}</span> Malicious
                          </div>
                          {report.report.data.attributes.last_analysis_stats.suspicious > 0 && (
                            <div className="text-amber-500">
                              <span className="font-medium">{report.report.data.attributes.last_analysis_stats.suspicious}</span> Suspicious
                            </div>
                          )}
                          <div className="text-muted-foreground">
                            <span className="font-medium">{report.report.data.attributes.last_analysis_stats.undetected}</span> Clean
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                
                {/* Threat Classification */}
                {report.report?.data?.attributes?.popular_threat_classification && (
                  <div className="bg-muted/20 rounded-md p-3 space-y-2">
                    <h3 className="text-sm font-medium">Threat Classification</h3>
                    {report.report.data.attributes.popular_threat_classification.suggested_threat_label && (
                      <div className="flex items-center">
                        <Badge variant="destructive" className="text-xs mr-2">
                          {report.report.data.attributes.popular_threat_classification.suggested_threat_label}
                        </Badge>
                        <span className="text-xs text-muted-foreground">Suggested threat label</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </Card>
        
        {/* Detailed Analysis Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {/* Detection Details */}
            {report.report?.data?.attributes?.last_analysis_results && (
              <Card className="p-6 bg-card/50 backdrop-blur border border-border/50 overflow-hidden relative">
                <div className="absolute -left-20 -bottom-20 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
                
                <div className="relative z-10">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-semibold flex items-center gap-2">
                      <Search className="w-5 h-5 text-primary" />
                      Detection Details
                    </h2>
                  </div>
                  
                  <div className="space-y-4">
                    {/* Malicious Detections */}
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium flex items-center text-destructive">
                        <AlertTriangle className="w-4 h-4 mr-1.5" />
                        Malicious Detections
                      </h3>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {Object.entries(report.report.data.attributes.last_analysis_results)
                          .filter(([_, result]: [string, any]) => result.category === "malicious")
                          .slice(0, 8) // Limit to top 8 for UI clarity
                          .map(([engine, result]: [string, any]) => (
                            <div 
                              key={engine}
                              className="bg-destructive/5 border border-destructive/20 rounded-md p-2 flex items-center justify-between"
                            >
                              <div>
                                <span className="text-sm font-medium">{engine}</span>
                                <p className="text-xs text-muted-foreground truncate max-w-[200px]">
                                  {result.result || "Generic Detection"}
                                </p>
                              </div>
                              <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0" />
                            </div>
                          ))
                        }
                      </div>
                      
                      {Object.entries(report.report.data.attributes.last_analysis_results)
                        .filter(([_, result]: [string, any]) => result.category === "malicious")
                        .length > 8 && (
                        <p className="text-xs text-muted-foreground text-center mt-2">
                          + {Object.entries(report.report.data.attributes.last_analysis_results)
                              .filter(([_, result]: [string, any]) => result.category === "malicious")
                              .length - 8} more detections
                        </p>
                      )}
                    </div>
                    
                    {/* Suspicious Detections */}
                    {Object.entries(report.report.data.attributes.last_analysis_results)
                      .filter(([_, result]: [string, any]) => result.category === "suspicious")
                      .length > 0 && (
                      <div className="space-y-2">
                        <h3 className="text-sm font-medium flex items-center text-amber-500">
                          <AlertTriangle className="w-4 h-4 mr-1.5" />
                          Suspicious Detections
                        </h3>
                        
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {Object.entries(report.report.data.attributes.last_analysis_results)
                            .filter(([_, result]: [string, any]) => result.category === "suspicious")
                            .map(([engine, result]: [string, any]) => (
                              <div 
                                key={engine}
                                className="bg-amber-500/5 border border-amber-500/20 rounded-md p-2 flex items-center justify-between"
                              >
                                <div>
                                  <span className="text-sm font-medium">{engine}</span>
                                  <p className="text-xs text-muted-foreground truncate max-w-[200px]">
                                    {result.result || "Suspicious Behavior"}
                                  </p>
                                </div>
                                <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />
                              </div>
                            ))
                          }
                        </div>
                      </div>
                    )}
                    
                    {/* Undetected Section preview */}
                    <div className="pt-3">
                      <h3 className="text-sm font-medium flex items-center text-muted-foreground">
                        <CheckCircle className="w-4 h-4 mr-1.5 text-muted-foreground/70" />
                        Undetected by {Object.entries(report.report.data.attributes.last_analysis_results)
                          .filter(([_, result]: [string, any]) => result.category === "undetected")
                          .length} engines
                      </h3>
                      
                      <div className="mt-2 flex flex-wrap gap-1">
                        {Object.entries(report.report.data.attributes.last_analysis_results)
                          .filter(([_, result]: [string, any]) => result.category === "undetected")
                          .slice(0, 12)
                          .map(([engine, _]: [string, any]) => (
                            <Badge 
                              key={engine} 
                              variant="outline" 
                              className="text-xs bg-muted/20 hover:bg-muted/30"
                            >
                              {engine}
                            </Badge>
                          ))
                        }
                        
                        {Object.entries(report.report.data.attributes.last_analysis_results)
                          .filter(([_, result]: [string, any]) => result.category === "undetected")
                          .length > 12 && (
                          <Badge variant="outline" className="text-xs bg-muted/10">
                            +{Object.entries(report.report.data.attributes.last_analysis_results)
                                .filter(([_, result]: [string, any]) => result.category === "undetected")
                                .length - 12} more
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            )}
            {report.feature_importances && report.feature_importances.length > 0 && (
            <FeatureImportanceCard featureImportances={report.feature_importances} />
          )}
          
            {/* Sandbox Detection */}
            {report.report?.data?.attributes?.sandbox_verdicts && 
             Object.keys(report.report.data.attributes.sandbox_verdicts).length > 0 && (
              <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-primary" />
                  Sandbox Analysis
                </h2>
                
                <div className="space-y-4">
                  {Object.entries(report.report.data.attributes.sandbox_verdicts).map(([sandbox, verdict]: [string, any]) => (
                    <div 
                      key={sandbox}
                      className={cn(
                        "border rounded-md p-3 flex items-start space-x-3",
                        verdict.category === "malicious" 
                          ? "bg-destructive/5 border-destructive/20" 
                          : "bg-muted/20 border-muted/30"
                      )}
                    >
                      {verdict.category === "malicious" ? (
                        <AlertTriangle className="w-5 h-5 text-destructive mt-0.5 flex-shrink-0" />
                      ) : (
                        <CheckCircle className="w-5 h-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                      )}
                      <div>
                        <h3 className="text-sm font-medium">{sandbox} Sandbox</h3>
                        <p className="text-sm text-muted-foreground mt-1">
                          Verdict: <span className={cn(
                            "font-medium",
                            verdict.category === "malicious" ? "text-destructive" : "text-muted-foreground"
                          )}>
                            {verdict.category.charAt(0).toUpperCase() + verdict.category.slice(1)}
                          </span>
                        </p>
                        
                        {verdict.malware_classification && verdict.malware_classification.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {verdict.malware_classification.map((classification: string, index: number) => (
                              <Badge 
                                key={index} 
                                variant={verdict.category === "malicious" ? "destructive" : "outline"}
                                className="text-xs"
                              >
                                {classification}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* BAT File Analysis */}
            {console.log("BAT analysis data:", report.bat_analysis)}
            {report.bat_analysis && (
              <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <FileWarning className="w-5 h-5 text-primary" />
                  BAT File Analysis
                </h2>
                
                <div className="space-y-4">
                  {/* BAT File Verdict */}
                  <div className={cn(
                    "border rounded-md p-3 flex items-start space-x-3",
                    report.bat_analysis.prediction.toLowerCase().includes("malware") 
                      ? "bg-destructive/5 border-destructive/20" 
                      : "bg-green-500/5 border-green-500/20"
                  )}>
                    {report.bat_analysis.prediction.toLowerCase().includes("malware") ? (
                      <AlertTriangle className="w-6 h-6 text-destructive mt-0.5 flex-shrink-0" />
                    ) : (
                      <CheckCircle className="w-6 h-6 text-green-500 mt-0.5 flex-shrink-0" />
                    )}
                    <div>
                      <h3 className="text-sm font-medium">Analysis Verdict</h3>
                      <p className="text-sm mt-1">
                        <span className={cn(
                          "font-medium",
                          report.bat_analysis.prediction.toLowerCase().includes("malware") ? "text-destructive" : "text-green-500"
                        )}>
                          {report.bat_analysis.prediction}
                        </span>
                        {report.bat_analysis.analysis_time !== undefined && (
                          <span className="text-xs text-muted-foreground ml-2">
                            (analyzed in {report.bat_analysis.analysis_time.toFixed(3)}s)
                          </span>
                        )}
                        {report.bat_analysis.risk_score !== undefined && (
                          <span className="text-xs text-muted-foreground ml-2">
                            (risk score: {report.bat_analysis.risk_score})
                          </span>
                        )}
                      </p>
                    </div>
                  </div>

                  {/* Dangerous Commands */}
                  {report.bat_analysis.dangerous_commands && report.bat_analysis.dangerous_commands.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium flex items-center text-destructive">
                        <AlertTriangle className="w-4 h-4 mr-1.5" />
                        Dangerous Commands
                      </h3>
                      
                      <div className="grid grid-cols-1 gap-2">
                        {report.bat_analysis.dangerous_commands.map((command: any, index: number) => (
                          <div 
                            key={index}
                            className="bg-destructive/5 border border-destructive/20 rounded-md p-2"
                          >
                            <code className="text-xs font-mono whitespace-pre-wrap break-all">
                              {command.content || command}
                              {command.line && <span className="text-muted-foreground ml-2">(line {command.line})</span>}
                            </code>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Handle both dangerous_commands and suspicious_commands for backward compatibility */}
                  {report.bat_analysis.suspicious_commands && report.bat_analysis.suspicious_commands.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium flex items-center text-destructive">
                        <AlertTriangle className="w-4 h-4 mr-1.5" />
                        Suspicious Commands
                      </h3>
                      
                      <div className="grid grid-cols-1 gap-2">
                        {report.bat_analysis.suspicious_commands.map((command: string, index: number) => (
                          <div 
                            key={index}
                            className="bg-destructive/5 border border-destructive/20 rounded-md p-2"
                          >
                            <code className="text-xs font-mono whitespace-pre-wrap break-all">{command}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Script Statistics */}
                  {report.bat_analysis.script_stats && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Script Statistics</h3>
                      <div className="grid grid-cols-2 gap-2">
                        {Object.entries(report.bat_analysis.script_stats).map(([key, value]: [string, any]) => (
                          <div key={key} className="bg-muted/20 rounded-md p-2">
                            <span className="text-xs text-muted-foreground capitalize">{key.replace(/_/g, ' ')}:</span>
                            <p className="text-sm font-medium mt-1">{value}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suspicious Patterns */}
                  {report.bat_analysis.suspicious_patterns && report.bat_analysis.suspicious_patterns.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Suspicious Patterns</h3>
                      <div className="flex flex-wrap gap-2">
                        {report.bat_analysis.suspicious_patterns.map((pattern: any, index: number) => (
                          <Badge 
                            key={index} 
                            variant="outline" 
                            className={cn(
                              "text-xs",
                              pattern.pattern && pattern.pattern.toLowerCase().includes("malicious") 
                                ? "bg-destructive/10 text-destructive border-destructive/30" 
                                : "bg-amber-500/10 text-amber-500 border-amber-500/30"
                            )}
                          >
                            {pattern.pattern || pattern}
                            {pattern.matches && <span className="ml-1">({pattern.matches})</span>}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Known Patterns (for backward compatibility) */}
                  {report.bat_analysis.known_patterns && report.bat_analysis.known_patterns.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium">Identified Patterns</h3>
                      <div className="flex flex-wrap gap-2">
                        {report.bat_analysis.known_patterns.map((pattern: string, index: number) => (
                          <Badge 
                            key={index} 
                            variant="outline" 
                            className={cn(
                              "text-xs",
                              pattern.toLowerCase().includes("malicious") 
                                ? "bg-destructive/10 text-destructive border-destructive/30" 
                                : "bg-amber-500/10 text-amber-500 border-amber-500/30"
                            )}
                          >
                            {pattern}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Obfuscation Score */}
                  {report.bat_analysis.obfuscation_score !== undefined && (
                    <div className="bg-muted/20 rounded-md p-3">
                      <h3 className="text-sm font-medium mb-2">Obfuscation Detection</h3>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-muted h-2 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-amber-500"
                            style={{ width: `${Math.min(100, report.bat_analysis.obfuscation_score * 100)}%` }}
                          ></div>
                        </div>
                        <span className="text-xs font-medium">
                          {report.bat_analysis.obfuscation_score >= 0.7 ? 'High' : 
                           report.bat_analysis.obfuscation_score >= 0.3 ? 'Medium' : 'Low'}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            )}
          </div>
          
          
          {/* Right Column */}
          <div className="space-y-6">
            {/* Threat Categories */}
            {report.report?.data?.attributes?.popular_threat_classification && (
              <>
                {/* Categories */}
                {report.report.data.attributes.popular_threat_classification.popular_threat_category && 
                 report.report.data.attributes.popular_threat_classification.popular_threat_category.length > 0 && (
                  <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                      <FileWarning className="w-5 h-5 text-primary" />
                      Threat Categories
                    </h2>
                    
                    <div className="space-y-4">
                      {report.report.data.attributes.popular_threat_classification.popular_threat_category.map((category: any, index: number) => (
                        <div
                          key={index}
                          className="flex items-center justify-between border-b border-border/30 pb-3 last:border-0 last:pb-0"
                        >
                          <div className="flex items-center gap-2">
                            <Badge variant="destructive" className="text-xs">
                              {category.value}
                            </Badge>
                            <span className="text-sm text-muted-foreground">
                              Reported by {category.count} engines
                            </span>
                          </div>
                          <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center text-destructive font-semibold text-sm animate-pulse">
                            {category.count}
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
                
                {/* Threat Names */}
                {report.report.data.attributes.popular_threat_classification.popular_threat_name && 
                 report.report.data.attributes.popular_threat_classification.popular_threat_name.length > 0 && (
                  <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-primary" />
                      Detected Threats
                    </h2>
                    
                    <div className="space-y-3">
                      {report.report.data.attributes.popular_threat_classification.popular_threat_name.map((name: any, index: number) => (
                        <div
                          key={index}
                          className="bg-destructive/5 border border-destructive/20 rounded-md p-3"
                        >
                          <div className="flex justify-between">
                            <span className="text-sm font-medium">{name.value}</span>
                            <Badge variant="destructive" className="text-xs">
                              {name.count}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </>
            )}
            
            
            
            {/* File Properties */}
            {report.report?.data?.attributes?.signature_info && (
              <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                <h2 className="text-lg font-semibold mb-4">File Properties</h2>
                
                <div className="space-y-2 text-sm">
                  {Object.entries(report.report.data.attributes.signature_info).map(([key, value]: [string, any]) => (
                    <div key={key} className="grid grid-cols-[1fr_2fr] gap-2">
                      <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}:</span>
                      <span className="font-medium truncate">{value}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
            
            {/* VirusTotal Link */}
            {report.file_hash && (
              <Card className="p-6 bg-primary/5 backdrop-blur border border-primary/20">
                <h2 className="text-lg font-semibold mb-3">External Resources</h2>
                
                <a 
                  href={`https://www.virustotal.com/gui/file/${report.file_hash}/detection`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between p-3 bg-background/50 rounded-md hover:bg-background/80 transition-colors group"
                >
                  <div className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    <span className="font-medium text-sm">View on VirusTotal</span>
                  </div>
                  <ArrowUpRight className="w-4 h-4 text-primary transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
                </a>
              </Card>
            )}

{report.mime_type && (
            <MimeTypeCard mimeInfo={report.mime_type} />
          )}


             


          </div>
          
        </div>
      </div>
    </div>
  );
} 