"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Upload,
  FileType,
  AlertTriangle,
  Shield,
  Microscope,
  ArrowUpRight,
  Loader2,
  Network,
  HardDrive,
  TerminalSquare,
  CheckCircle,
  Timer,
  Zap
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DynamicReport } from "@/types/types";

export default function DynamicAnalysisPage() {
  const router = useRouter();
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysisStatus, setAnalysisStatus] = useState<'idle' | 'uploading' | 'analyzing' | 'complete' | 'failed'>('idle');
  const [dynamicReport, setDynamicReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // For polling analysis status
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
  }, []);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = Array.from(e.dataTransfer.files);
    if (files?.length) {
      setFile(files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const startDynamicAnalysis = async () => {
    if (!file) return;
    
    try {
      setUploading(true);
      setAnalysisStatus('uploading');
      setProgress(10);
      
      const formData = new FormData();
      formData.append('file', file);
      
      // Upload directly to dynamic-specific endpoint
      setProgress(30);
      console.log("Uploading file to dynamic-submit...");
      const uploadResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/dynamic-submit`, {
        method: 'POST',
        body: formData,
      });
      
      if (!uploadResponse.ok) {
        throw new Error(`Upload failed: ${uploadResponse.status}`);
      }
      
      const uploadData = await uploadResponse.json();
      console.log("Upload response:", uploadData);
      setProgress(50);
      setAnalysisStatus('analyzing');
      
      // Try a direct synchronous approach first (like Streamlit version)
      if (uploadData.file_hash) {
        console.log("Starting direct synchronous polling with file_hash");
        setProgress(70);
        
        // Synchronous approach similar to Streamlit - poll directly until we get a result
        let attempts = 0;
        const maxAttempts = 30; // Try for up to 5 minutes (30 * 10s)
        
        while (attempts < maxAttempts) {
          attempts++;
          console.log(`Synchronous polling attempt ${attempts}/${maxAttempts}`);
          
          try {
            // Try direct lookup with the overview endpoint, just like the Streamlit version
            const directResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/overview/${uploadData.file_hash}`);
            
            if (directResponse.ok) {
              const directData = await directResponse.json();
              console.log("Direct overview response:", directData);
              
              if (directData.verdict) {
                console.log("Analysis complete via direct lookup!");
                
                // Filter out unwanted scanners
                const filteredScanners = directData.scanners_v2 ? { ...directData.scanners_v2 } : {};
                // Remove specific scanners
                delete filteredScanners.bfore_ai;
                delete filteredScanners.clean_dns;
                delete filteredScanners.criminal_ip;
                delete filteredScanners.crowdstrike_ml;
                
                // Process the data into what we need for display
                const report: DynamicReport = {
                  hash: uploadData.file_hash || directData.sha256,
                  verdict: directData.verdict || 'unknown',
                  filename: directData.last_file_name || file.name,
                  scan_time: directData.scan_time || directData.analysis_time || 0,
                  threat_score: directData.threat_score || 0,
                  classification: directData.vx_family ? [directData.vx_family] : [],
                  signatures: directData.signatures || [],
                  scanners_v2: filteredScanners,
                  network: directData.network || { connections: [] },
                  filesystem: directData.filesystem || [],
                  processes: directData.processes || [],
                  environment: {
                    os: "Windows 10",
                    architecture: directData.architecture || "x64"
                  }
                };
                
                setDynamicReport(report);
                setAnalysisStatus('complete');
                setProgress(100);
                setUploading(false);
                return;
              }
            }
          } catch (e) {
            console.error("Error in direct lookup:", e);
            // Continue trying - don't throw an error yet
          }
          
          // Wait 10 seconds before trying again
          await new Promise(resolve => setTimeout(resolve, 10000));
        }
        
        // If we get here, we timed out after 30 attempts
        console.log("Synchronous polling timed out, falling back to job_id polling");
      }
      
      // Fall back to job_id polling if direct approach timed out or wasn't available
      if (uploadData.job_id) {
        setAnalysisId(uploadData.job_id);
        
        pollingIntervalRef.current = setInterval(async () => {
          try {
            console.log(`Checking status for job ${uploadData.job_id}...`);
            const statusResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/dynamic-status/${uploadData.job_id}`);
            
            if (!statusResponse.ok) {
              throw new Error(`Status check returned ${statusResponse.status}`);
            }
            
            const statusData = await statusResponse.json();
            console.log("Status response:", statusData);
            
            if (statusData.status === 'completed') {
              // Analysis is complete, fetch the report
              console.log(`Analysis complete! Fetching report for ${uploadData.file_hash}`);
              const reportResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'}/dynamic-report/${uploadData.file_hash}`);
              
              if (!reportResponse.ok) {
                throw new Error(`Report fetch failed: ${reportResponse.status}`);
              }
              
              const reportData = await reportResponse.json();
              console.log("Report data:", reportData);
              
              // Filter out unwanted scanners if they exist
              if (reportData.scanners_v2) {
                delete reportData.scanners_v2.bfore_ai;
                delete reportData.scanners_v2.clean_dns;
                delete reportData.scanners_v2.criminal_ip;
                delete reportData.scanners_v2.crowdstrike_ml;
              }
              
              setDynamicReport(reportData);
              setAnalysisStatus('complete');
              
              if (pollingIntervalRef.current) {
                clearInterval(pollingIntervalRef.current);
                pollingIntervalRef.current = null;
              }
            } else if (statusData.status === 'failed') {
              setError('Dynamic analysis failed. The sandbox could not analyze this file.');
              setAnalysisStatus('failed');
              
              if (pollingIntervalRef.current) {
                clearInterval(pollingIntervalRef.current);
                pollingIntervalRef.current = null;
              }
            } else {
              console.log("Analysis still pending...");
            }
            // If still analyzing, continue polling
          } catch (error) {
            console.error('Error checking analysis status:', error);
            setError(error instanceof Error ? error.message : 'Error checking analysis status');
            setAnalysisStatus('failed');
            
            if (pollingIntervalRef.current) {
              clearInterval(pollingIntervalRef.current);
              pollingIntervalRef.current = null;
            }
          }
        }, 10000); // Poll every 10 seconds like in the Streamlit version
      } else {
        throw new Error('No analysis ID returned from the server');
      }
      
      setProgress(100);
    } catch (error) {
      console.error('Error starting dynamic analysis:', error);
      setError(error instanceof Error ? error.message : 'Unknown error starting dynamic analysis');
      setAnalysisStatus('failed');
    } finally {
      setUploading(false);
    }
  };

  const isMalicious = () => {
    if (!dynamicReport) return false;
    return dynamicReport.verdict === 'malicious' || dynamicReport.threat_score > 70;
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto p-6 space-y-8">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div className="space-y-1">
            <h1 className="text-4xl font-bold flex items-center gap-2">
              <Microscope className="h-8 w-8 text-primary" />
              Dynamic Sandbox Analysis
            </h1>
            <p className="text-muted-foreground">
              Execute files in isolated sandbox environment to detect malicious behaviors
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary" />
            <span className="text-sm font-medium text-muted-foreground">Advanced Behavioral Detection</span>
          </div>
        </div>

        {/* Dynamic Sandbox Advantage Card */}
        <Card className="p-6 bg-primary/5 border border-primary/20 overflow-hidden relative">
          <div className="absolute -right-20 -top-20 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
          
          <div className="relative z-10">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              Why Dynamic Sandbox Analysis?
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="flex flex-col space-y-2">
                <div className="p-2 bg-primary/10 rounded-full w-fit">
                  <Microscope className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-medium">Runtime Behavior Detection</h3>
                <p className="text-sm text-muted-foreground">
                  Observe actual code execution instead of relying on signatures or static patterns, catching zero-day threats.
                </p>
              </div>
              
              <div className="flex flex-col space-y-2">
                <div className="p-2 bg-primary/10 rounded-full w-fit">
                  <Shield className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-medium">Isolated Environment</h3>
                <p className="text-sm text-muted-foreground">
                  Files execute in a contained sandbox environment, eliminating any risk to your system.
                </p>
              </div>
              
              <div className="flex flex-col space-y-2">
                <div className="p-2 bg-primary/10 rounded-full w-fit">
                  <Network className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-medium">Comprehensive Monitoring</h3>
                <p className="text-sm text-muted-foreground">
                  Track network connections, file operations, registry changes, and process activities.
                </p>
              </div>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Upload Area & Results */}
          <div className="lg:col-span-2 space-y-6">
            {/* Upload Area */}
            {analysisStatus === 'idle' && (
              <Card
                className={cn(
                  "h-[300px] flex flex-col items-center justify-center border-2 border-dashed rounded-lg transition-colors relative group",
                  dragActive ? "border-primary bg-primary/5" : "border-border/50 hover:border-border"
                )}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                <div className="absolute -inset-1 bg-gradient-to-r from-primary via-secondary to-primary rounded-lg blur-lg opacity-0 group-hover:opacity-20 transition duration-500 pointer-events-none"></div>
                <div className="relative z-10 flex flex-col items-center justify-center text-center p-4">
                  <input
                    type="file"
                    className="hidden"
                    id="file-upload"
                    onChange={handleFileChange}
                  />
                  <label
                    htmlFor="file-upload"
                    className="flex flex-col items-center justify-center cursor-pointer"
                  >
                    <div className="p-3 bg-primary/10 rounded-full mb-4 border border-primary/20">
                      <Upload className="w-10 h-10 text-primary" />
                    </div>
                    <p className="text-lg font-medium">Drag & Drop or Click to Upload</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      Upload a file for dynamic sandbox analysis
                    </p>
                  </label>
                </div>
              </Card>
            )}

            {/* File Selected */}
            {file && analysisStatus === 'idle' && (
              <Card className="p-4 bg-card/50 backdrop-blur border border-border/50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <FileType className="w-6 h-6 text-primary" />
                    <div>
                      <p className="text-sm font-medium">{file.name}</p>
                      <p className="text-xs text-muted-foreground">{(file.size / 1024).toFixed(2)} KB</p>
                    </div>
                  </div>
                  <Button onClick={startDynamicAnalysis}>
                    <Microscope className="w-4 h-4 mr-2" />
                    Start Sandbox Analysis
                  </Button>
                </div>
              </Card>
            )}

            {/* Upload/Analysis Progress */}
            {(analysisStatus === 'uploading' || analysisStatus === 'analyzing') && (
              <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {analysisStatus === 'uploading' ? (
                        <Loader2 className="w-6 h-6 text-primary animate-spin" />
                      ) : (
                        <Microscope className="w-6 h-6 text-primary animate-pulse" />
                      )}
                      <div>
                        <p className="text-sm font-medium">
                          {analysisStatus === 'uploading' ? 'Uploading file...' : 'Running sandbox analysis...'}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {analysisStatus === 'uploading' 
                            ? 'Preparing file for analysis' 
                            : 'Executing in isolated environment and monitoring behavior'}
                        </p>
                      </div>
                    </div>
                    {analysisStatus === 'analyzing' && (
                      <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30">
                        <Timer className="w-3.5 h-3.5 mr-1.5 animate-pulse" />
                        Running
                      </Badge>
                    )}
                  </div>

                  {analysisStatus === 'uploading' && (
                    <Progress value={progress} className="h-1.5 bg-primary/20" />
                  )}

                  {analysisStatus === 'analyzing' && (
                    <div className="bg-muted/30 p-4 rounded-md space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium">Monitoring file operations</span>
                        <HardDrive className="w-4 h-4 text-primary animate-pulse" />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium">Analyzing network connections</span>
                        <Network className="w-4 h-4 text-primary animate-pulse" />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium">Tracking process execution</span>
                        <TerminalSquare className="w-4 h-4 text-primary animate-pulse" />
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            )}

            {/* Error State */}
            {error && (
              <Card className="p-4 bg-destructive/10 text-destructive-foreground border border-destructive/30">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5" />
                  <p className="font-medium text-sm">{error}</p>
                </div>
              </Card>
            )}

            {/* Analysis Results */}
            {analysisStatus === 'complete' && dynamicReport && (
              <>
                {/* Results Header */}
                <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                      <h2 className="text-xl font-semibold flex items-center gap-2">
                        {isMalicious() ? (
                          <AlertTriangle className="w-6 h-6 text-destructive" />
                        ) : (
                          <CheckCircle className="w-6 h-6 text-green-500" />
                        )}
                        Dynamic Analysis Results
                      </h2>
                      <p className="text-sm text-muted-foreground mt-1">
                        File: {file?.name}
                      </p>
                    </div>
                    
                    {/* <div className="flex items-center gap-3">
                      <div className="text-center px-4 py-2 bg-muted/20 rounded-md">
                        <p className="text-xs text-muted-foreground">Execution Time</p>
                        <p className="text-base font-medium">
                          {dynamicReport.scan_time ? `${dynamicReport.scan_time}s` : '??s'}
                        </p>
                      </div>
                      
                      <Badge 
                        variant={isMalicious() ? "destructive" : "outline"} 
                        className={cn(
                          "text-sm px-3 py-1",
                          !isMalicious() && "bg-green-500/10 text-green-500 border-green-500/30"
                        )}
                      >
                        {isMalicious() ? 'Malicious' : 'Clean'}
                      </Badge>
                    </div> */}
                  </div>
                </Card>
                
                {/* Threat Score Card */}
                {dynamicReport.threat_score !== undefined && (
                  <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                    <h3 className="text-lg font-semibold mb-4">Threat Assessment</h3>
                    
                    <div className="mb-6">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-sm">Threat Score</span>
                        <span 
                          className={cn(
                            "text-lg font-semibold",
                            dynamicReport.threat_score > 70 ? "text-destructive" : 
                            dynamicReport.threat_score > 30 ? "text-amber-500" : 
                            "text-green-500"
                          )}
                        >
                          {dynamicReport.threat_score}/100
                        </span>
                      </div>
                      
                      <div className="h-4 bg-muted/20 rounded-full overflow-hidden">
                        <div 
                          className={cn(
                            "h-full transition-all duration-1000",
                            dynamicReport.threat_score > 70 ? "bg-destructive" : 
                            dynamicReport.threat_score > 30 ? "bg-amber-500" : 
                            "bg-green-500"
                          )}
                          style={{ width: `${dynamicReport.threat_score}%` }}
                        ></div>
                      </div>
                    </div>
                    
                    {/* Classification Tags */}
                    {dynamicReport.classification && dynamicReport.classification.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium mb-2">Malware Classification</h4>
                        <div className="flex flex-wrap gap-2">
                          {dynamicReport.classification.map((category: string, index: number) => (
                            <Badge 
                              key={index} 
                              variant={isMalicious() ? "destructive" : "outline"}
                              className={cn(
                                "text-sm",
                                isMalicious() && "bg-destructive/10"
                              )}
                            >
                              {category}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                )}
                
                {/* Detailed Results in Tabs */}
                <Tabs defaultValue="behavior" className="w-full">
                  <TabsList className="grid w-full grid-cols-4 mb-6">
                    <TabsTrigger value="behavior">Behaviors</TabsTrigger>
                    <TabsTrigger value="network">Network</TabsTrigger>
                    <TabsTrigger value="filesystem">File System</TabsTrigger>
                    <TabsTrigger value="processes">Processes</TabsTrigger>
                  </TabsList>
                  
                  {/* Behavioral Tab */}
                  <TabsContent value="behavior" className="space-y-6">
                    <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                      <h2 className="text-lg font-semibold mb-4">Scanner Results</h2>
                      
                      {dynamicReport.scanners_v2 ? (
                        <div className="space-y-4">
                          {Object.entries(dynamicReport.scanners_v2 || {})
                            .filter(([_, scanner]: [string, any]) => scanner !== null)
                            .map(([name, scanner]: [string, any], index: number) => (
                              <div 
                                key={index}
                                className={cn(
                                  "border rounded-md p-4",
                                  scanner.status === "malicious" ? "bg-destructive/5 border-destructive/20" :
                                  scanner.status === "suspicious" ? "bg-amber-500/5 border-amber-500/20" :
                                  "bg-muted/20 border-border/30"
                                )}
                              >
                                <div className="flex items-start gap-3">
                                  {scanner.status === "malicious" ? (
                                    <AlertTriangle className="w-5 h-5 text-destructive mt-0.5 flex-shrink-0" />
                                  ) : scanner.status === "suspicious" ? (
                                    <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" />
                                  ) : (
                                    <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 flex-shrink-0" />
                                  )}
                                  
                                  <div>
                                    <h3 className="text-sm font-medium">{scanner.name || name}</h3>
                                    {scanner.positives !== null && scanner.total !== null && (
                                      <p className="text-xs text-muted-foreground mt-1">
                                        {scanner.positives}/{scanner.total} engines detected this file as malicious
                                      </p>
                                    )}
                                  </div>
                                  
                                  <div className="ml-auto flex-shrink-0">
                                    <Badge
                                      variant={
                                        scanner.status === "malicious" ? "destructive" :
                                        scanner.status === "suspicious" ? "default" :
                                        "outline"
                                      }
                                      className="text-xs capitalize"
                                    >
                                      {scanner.status || "unknown"}
                                    </Badge>
                                  </div>
                                </div>
                              </div>
                            ))}
                        </div>
                      ) : dynamicReport.signatures && dynamicReport.signatures.length > 0 ? (
                        <div className="space-y-4">
                          {dynamicReport.signatures.map((signature: any, index: number) => (
                            <div 
                              key={index}
                              className={cn(
                                "border rounded-md p-4",
                                signature.severity === "high" ? "bg-destructive/5 border-destructive/20" :
                                signature.severity === "medium" ? "bg-amber-500/5 border-amber-500/20" :
                                "bg-muted/20 border-border/30"
                              )}
                            >
                              <div className="flex items-start gap-3">
                                {signature.severity === "high" ? (
                                  <AlertTriangle className="w-5 h-5 text-destructive mt-0.5 flex-shrink-0" />
                                ) : signature.severity === "medium" ? (
                                  <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" />
                                ) : (
                                  <AlertTriangle className="w-5 h-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                                )}
                                
                                <div>
                                  <h3 className="text-sm font-medium">{signature.description}</h3>
                                  <p className="text-xs text-muted-foreground mt-1">
                                    {signature.detail || "No additional details"}
                                  </p>
                                  
                                  {signature.mitre_tactics && (
                                    <div className="flex flex-wrap gap-1 mt-2">
                                      {signature.mitre_tactics.map((tactic: string, idx: number) => (
                                        <Badge 
                                          key={idx} 
                                          variant="outline" 
                                          className="text-xs bg-background/50"
                                        >
                                          {tactic}
                                        </Badge>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                
                                <div className="ml-auto flex-shrink-0">
                                  <Badge
                                    variant={
                                      signature.severity === "high" ? "destructive" :
                                      signature.severity === "medium" ? "default" :
                                      "outline"
                                    }
                                    className="text-xs capitalize"
                                  >
                                    {signature.severity || "low"} severity
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : isMalicious() ? (
                        <div className="space-y-4">
                          <div className="border rounded-md p-4 bg-destructive/5 border-destructive/20">
                            <div className="flex items-start gap-3">
                              <AlertTriangle className="w-5 h-5 text-destructive mt-0.5 flex-shrink-0" />
                              <div>
                                <h3 className="text-sm font-medium">File identified as malicious</h3>
                                <p className="text-xs text-muted-foreground mt-1">
                                  This file was flagged as malicious with a threat score of {dynamicReport.threat_score}/100
                                </p>
                                {dynamicReport.classification && dynamicReport.classification.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-2">
                                    {dynamicReport.classification.map((category: string, idx: number) => (
                                      <Badge 
                                        key={idx} 
                                        variant="destructive" 
                                        className="text-xs bg-destructive/10"
                                      >
                                        {category}
                                      </Badge>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="text-center py-4 text-muted-foreground">
                            <p className="text-sm">No detailed behavioral data available</p>
                          </div>
                        </div>
                      ) : (
                        <div className="text-center py-10">
                          <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-500 opacity-80" />
                          <p className="text-base text-muted-foreground">No suspicious behaviors detected</p>
                        </div>
                      )}
                    </Card>
                    
                    {/* Classification Information */}
                    {dynamicReport.classification && dynamicReport.classification.length > 0 && (
                      <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                        <h2 className="text-lg font-semibold mb-4">Malware Classification</h2>
                        <div className="space-y-3">
                          {dynamicReport.classification.map((category: string, index: number) => (
                            <div key={index} className="flex items-center gap-2 p-3 bg-destructive/5 rounded-md border border-destructive/20">
                              <Shield className="w-5 h-5 text-destructive" />
                              <span className="font-medium">{category}</span>
                            </div>
                          ))}
                          {isMalicious() && (
                            <p className="text-sm text-muted-foreground mt-2">
                              This file has been classified as potentially malicious software
                            </p>
                          )}
                        </div>
                      </Card>
                    )}
                  </TabsContent>
                  
                  {/* Network Tab */}
                  <TabsContent value="network" className="space-y-6">
                    <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                      <h2 className="text-lg font-semibold mb-4">Network Communications</h2>
                      
                      {dynamicReport.network && dynamicReport.network.connections && 
                      dynamicReport.network.connections.length > 0 ? (
                        <div className="space-y-4">
                          {dynamicReport.network.connections.map((connection: any, index: number) => (
                            <div 
                              key={index}
                              className="bg-muted/20 border border-border/30 rounded-md p-3"
                            >
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant={connection.malicious ? "destructive" : "outline"} 
                                    className="text-xs"
                                  >
                                    {connection.protocol || "TCP"}
                                  </Badge>
                                  <span className="text-sm font-medium">
                                    {connection.destination_ip || connection.hostname}
                                  </span>
                                </div>
                                <span className="text-xs text-muted-foreground">
                                  Port: {connection.port || "Unknown"}
                                </span>
                              </div>
                              
                              {connection.url && (
                                <div className="mt-2 pt-2 border-t border-border/20">
                                  <span className="text-xs text-muted-foreground block mb-1">URL</span>
                                  <p className="text-xs font-mono bg-background/50 p-1.5 rounded overflow-x-auto whitespace-nowrap">
                                    {connection.url}
                                  </p>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="bg-muted/20 rounded-md p-4 text-center">
                          <p className="text-sm">No network connections observed during analysis</p>
                        </div>
                      )}
                    </Card>
                  </TabsContent>
                  
                  {/* File System Tab */}
                  <TabsContent value="filesystem" className="space-y-6">
                    <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                      <h2 className="text-lg font-semibold mb-4">File System Activity</h2>
                      
                      {dynamicReport.filesystem && dynamicReport.filesystem.length > 0 ? (
                        <div className="space-y-1">
                          <div className="grid grid-cols-[auto_1fr_auto] gap-2 text-xs font-medium bg-muted/30 p-2 rounded-t-md">
                            <div>Operation</div>
                            <div>Path</div>
                            <div>Status</div>
                          </div>
                          
                          <div className="max-h-96 overflow-y-auto bg-muted/10 rounded-b-md">
                            {dynamicReport.filesystem.map((activity: any, index: number) => (
                              <div 
                                key={index}
                                className={cn(
                                  "grid grid-cols-[auto_1fr_auto] gap-2 text-xs p-2 border-b border-border/10 last:border-0",
                                  activity.malicious && "bg-destructive/5"
                                )}
                              >
                                <div className="font-medium whitespace-nowrap">
                                  <Badge
                                    variant={
                                      activity.operation === "write" || activity.operation === "create" ? "default" :
                                      activity.operation === "delete" ? "destructive" :
                                      "outline"
                                    }
                                    className="text-xs capitalize"
                                  >
                                    {activity.operation}
                                  </Badge>
                                </div>
                                <div className="font-mono truncate" title={activity.path}>{activity.path}</div>
                                <div>{activity.status || "Success"}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <div className="bg-muted/20 rounded-md p-4 text-center">
                          <p className="text-sm">No file system activity observed during analysis</p>
                        </div>
                      )}
                    </Card>
                  </TabsContent>
                  
                  {/* Processes Tab */}
                  <TabsContent value="processes" className="space-y-6">
                    <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
                      <h2 className="text-lg font-semibold mb-4">Process Activity</h2>
                      
                      {dynamicReport.processes && dynamicReport.processes.length > 0 ? (
                        <div className="space-y-4">
                          {dynamicReport.processes.map((process: any, index: number) => (
                            <div 
                              key={index}
                              className={cn(
                                "border rounded-md p-3",
                                process.malicious ? "bg-destructive/5 border-destructive/20" : "bg-muted/20 border-border/30"
                              )}
                            >
                              <div className="flex items-start justify-between">
                                <div>
                                  <h3 className="text-sm font-medium">{process.name}</h3>
                                  <p className="text-xs text-muted-foreground mt-1">
                                    PID: {process.pid || "Unknown"}
                                  </p>
                                  {process.command_line && (
                                    <div className="mt-2">
                                      <span className="text-xs text-muted-foreground block mb-1">Command Line</span>
                                      <p className="text-xs font-mono bg-background/50 p-1.5 rounded overflow-x-auto">
                                        {process.command_line}
                                      </p>
                                    </div>
                                  )}
                                </div>
                                
                                <div className="flex-shrink-0">
                                  {process.malicious && (
                                    <Badge variant="destructive" className="text-xs">
                                      Suspicious
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="bg-muted/20 rounded-md p-4 text-center">
                          <p className="text-sm">No process activity recorded during analysis</p>
                        </div>
                      )}
                    </Card>
                  </TabsContent>
                </Tabs>
              </>
            )}
          </div>

          {/* Right Column: Info & Stats */}
          <div className="space-y-6">
            {/* Sandbox Environment Card */}
            <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
              <h2 className="text-lg font-semibold mb-4">Sandbox Environment</h2>
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <TerminalSquare className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">Isolated Execution</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Files run in a completely isolated virtual machine with no access to your system.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <HardDrive className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">Deep Monitoring</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      All file, registry, network and process operations are intercepted and analyzed.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Shield className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">Enhanced Detection</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Our sandbox can detect advanced evasive malware that tries to hide from analysis.
                    </p>
                  </div>
                </div>
              </div>
            </Card>

            {/* How It Works Card */}
            <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
              <h2 className="text-lg font-semibold mb-4">How It Works</h2>
              
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center font-medium">1</div>
                  <div>
                    <h3 className="text-sm font-medium">Upload File</h3>
                    <p className="text-xs text-muted-foreground">Your file is securely transferred to our sandbox</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center font-medium">2</div>
                  <div>
                    <h3 className="text-sm font-medium">Execute in Sandbox</h3>
                    <p className="text-xs text-muted-foreground">File runs in isolated environment with full monitoring</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center font-medium">3</div>
                  <div>
                    <h3 className="text-sm font-medium">Monitor Behavior</h3>
                    <p className="text-xs text-muted-foreground">All activity is logged and analyzed for malicious patterns</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center font-medium">4</div>
                  <div>
                    <h3 className="text-sm font-medium">Generate Report</h3>
                    <p className="text-xs text-muted-foreground">Detailed analysis of behavior with threat assessment</p>
                  </div>
                </div>
              </div>
            </Card>

            {/* Supported File Types */}
            <Card className="p-6 bg-card/50 backdrop-blur border border-border/50">
              <h2 className="text-lg font-semibold mb-4">Supported File Types</h2>
              
              <div className="grid grid-cols-2 gap-2">
                <Badge variant="outline" className="justify-start">Executables (.exe, .dll)</Badge>
                <Badge variant="outline" className="justify-start">Documents (.pdf, .doc)</Badge>
                <Badge variant="outline" className="justify-start">Scripts (.js, .vbs, .ps1)</Badge>
                <Badge variant="outline" className="justify-start">Office (.docx, .xlsx)</Badge>
                <Badge variant="outline" className="justify-start">Archives (.zip, .rar)</Badge>
                <Badge variant="outline" className="justify-start">Java (.jar, .class)</Badge>
              </div>
              
              <div className="mt-4 text-xs text-muted-foreground">
                <p>Max file size: 32MB</p>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}