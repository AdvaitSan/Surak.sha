"use client";

import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Upload,
  FileType,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Info,
  Shield,
  FileScan,
  Clock,
  FileIcon,
  BrainCircuit,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";

// Define types for scan results
interface ScanResult {
  id: string;
  filename: string;
  file_hash?: string;
  analysis_id?: string;
  status: 'pending' | 'complete' | 'failed' | 'error' | 'ml_only';
  report?: any;
  error?: string;
  timestamp: Date;
  startTime: number;
  duration?: number;
  ml_prediction?: string | {
    prediction: string;
    analysis_time?: number;
    feature_importances?: any;
  };
  ml_prediction_time?: number;
  mime_type?: { mime_type: string; mime_category: string; mime_description: string };
  feature_importances?: FeatureImportance[];
  bat_analysis?: {
    prediction: string;
    suspicious_commands: string[];
    known_patterns: string[];
  };
}

interface FeatureImportance {
  feature: string;
  importance: number;
  description?: string;
}

// Add FeatureImportanceChart component
const FeatureImportanceChart = ({ featureImportances }: { featureImportances: FeatureImportance[] }) => {
  if (!featureImportances || featureImportances.length === 0) return null;
  
  // Sort by importance for better visualization
  const sortedFeatures = [...featureImportances].sort((a, b) => b.importance - a.importance).slice(0, 5);
  
  return (
    <div className="mt-3 pt-3 border-t border-border/20">
      <h4 className="text-xs font-semibold mb-2">Top Feature Importances:</h4>
      <div className="space-y-2">
        {sortedFeatures.map((feature, idx) => (
          <div key={idx} className="space-y-1">
            <div className="flex justify-between items-center text-xs">
              <span title={feature.description || ""} className="truncate max-w-[80%]">
                {feature.feature}
              </span>
              <span className="font-mono">{feature.importance.toFixed(4)}</span>
            </div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
              <div 
                className="h-full bg-primary rounded-full"
                style={{ width: `${Math.min(100, feature.importance * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Component to display MIME type specific info
const MimeTypeInfo = ({ mimeInfo }: { mimeInfo: any }) => {
  if (!mimeInfo) return null;
  
  return (
    <div className="text-xs text-muted-foreground mt-2 border-t border-border/20 pt-2">
      <p className="flex items-center">
        <FileIcon className="w-3 h-3 mr-1 inline" />
        {mimeInfo.mime_category && (
          <span className="mr-1.5 font-medium">{mimeInfo.mime_category}:</span>
        )}
        {mimeInfo.mime_description && (
          <span className="italic">{mimeInfo.mime_description}</span>
        )}
      </p>
    </div>
  );
};

export default function FileUpload() {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  // scanResults stores finalized results for display in "Recent Scans"
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  // currentScans tracks uploads currently in progress (pending or just uploaded)
  const [currentScans, setCurrentScans] = useState<ScanResult[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [mlResults, setMlResults] = useState<ScanResult[]>([]);

  // Ref to store start times for pending uploads before scan objects are created
  const uploadStartTimes = useRef<Record<string, number>>({});

  useEffect(() => {
    const pendingScans = currentScans.filter(scan => scan.status === 'pending');

    if (pendingScans.length === 0) return;

    const intervalId = setInterval(async () => {
      console.log("Polling for pending scans...");
      
      // Check each pending scan individually and update states progressively
      await Promise.all(
        pendingScans.map(async (scan) => {
          if (!scan.analysis_id) return;

          try {
            const response = await fetch(`http://localhost:5000/analysis/${scan.analysis_id}`);
            if (!response.ok) return;

            const data = await response.json();
            
            if (data.data?.attributes?.status === 'completed') {
              const reportResponse = await fetch(`http://localhost:5000/report/${scan.file_hash}`);
              const reportData = await reportResponse.json();

              const completedScan: ScanResult = {
                ...scan,
                status: 'complete',
                report: reportData.report,
                timestamp: new Date(),
                duration: Date.now() - scan.startTime,
                ml_prediction: reportData.ml_prediction || scan.ml_prediction,
                ml_prediction_time: reportData.ml_prediction_time || scan.ml_prediction_time
              };

              // Immediately update UI for this completed scan
              setScanResults(prev => {
                const newResults = [completedScan, ...prev.filter(s => s.id !== scan.id)].slice(0, 10);
                return newResults;
              });
              
              // Remove from currentScans
              setCurrentScans(prev => prev.filter(s => s.id !== scan.id));
              
              // Remove from ML results if it exists there
              if (scan.file_hash) {
                setMlResults(prev => prev.filter(r => r.file_hash !== scan.file_hash));
              }
            } else if (data.data?.attributes?.status === 'failed') {
              const failedScan: ScanResult = { 
                ...scan, 
                status: 'failed', 
                error: 'VirusTotal analysis failed',
                timestamp: new Date()
              };
              
              // Immediately update UI for this failed scan
              setScanResults(prev => {
                const newResults = [failedScan, ...prev.filter(s => s.id !== scan.id)].slice(0, 10);
                return newResults;
              });
              
              // Remove from currentScans
              setCurrentScans(prev => prev.filter(s => s.id !== scan.id));
            }
          } catch (error) {
            console.error(`Error polling scan ${scan.analysis_id}:`, error);
          }
        })
      );
    }, 5000); // Poll every 5 seconds for faster UI updates

    return () => clearInterval(intervalId);
  }, [currentScans]); // Rerun effect when currentScans changes

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
      handleUpload(files, files.length > 1);
    }
  };

  const handleUpload = async (files: File[], isBatch: boolean = false) => {
    setUploading(true);
    setProgress(10);
    setErrorMessage(null);
    const uploadInitiationTime = Date.now(); // Record time before API call

    // Store start times keyed by filename temporarily
    files.forEach(file => {
      uploadStartTimes.current[file.name] = uploadInitiationTime;
    });

    try {
      const formData = new FormData();

      if (isBatch) {
        // For batch uploads, process one file at a time to provide progressive feedback
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          const singleFormData = new FormData();
          singleFormData.append('file', file);
          const startTime = uploadStartTimes.current[file.name] || uploadInitiationTime;
          const scanIdBase = `${file.name}-${startTime}`;
          
          // Update progress based on file index
          const progressValue = 10 + Math.floor((i / files.length) * 80);
          setProgress(progressValue);
          
          try {
            // Create a temporary pending scan to show in the queue immediately
            const tempScan: ScanResult = {
              id: `temp-${scanIdBase}`,
              filename: file.name,
              status: 'pending',
              timestamp: new Date(),
              startTime: startTime
            };
            
            // Add to current scans immediately to show progress
            setCurrentScans(prev => [tempScan, ...prev]);
            
            // Upload each file individually
            const response = await fetch('http://localhost:5000/upload', {
              method: 'POST',
              body: singleFormData,
            });
            
            if (!response.ok) {
              throw new Error(`Upload failed for ${file.name}: ${response.status}`);
            }
            
            const data = await response.json();
            const scanId = data.file_hash || data.analysis_id || scanIdBase;
            
            // Remove temp scan
            setCurrentScans(prev => prev.filter(s => s.id !== `temp-${scanIdBase}`));
            
            // Immediately display ML results if available
            if (data.ml_prediction) {
              const mlResult: ScanResult = {
                id: `ml-${data.file_hash}`,
                filename: file.name,
                file_hash: data.file_hash,
                status: 'ml_only',
                timestamp: new Date(),
                startTime: startTime,
                ml_prediction: data.ml_prediction,
                ml_prediction_time: data.ml_prediction_time
              };
              setMlResults(prev => [mlResult, ...prev].slice(0, 10));
            }
            
            // Handle different response types
            if (data.status === 'pending') {
              const newScan: ScanResult = {
                id: scanId,
                filename: file.name,
                file_hash: data.file_hash,
                analysis_id: data.analysis_id,
                status: 'pending',
                timestamp: new Date(),
                startTime: startTime,
                ml_prediction: data.ml_prediction,
                ml_prediction_time: data.ml_prediction_time,
                mime_type: data.mime_type,
                feature_importances: data.feature_importances,
                bat_analysis: data.bat_analysis,
              };
              setCurrentScans(prev => [newScan, ...prev]);
            } else if (data.status === 'complete') {
              const endTime = Date.now();
              const duration = endTime - startTime;
              const newResult: ScanResult = {
                id: scanId,
                filename: file.name,
                file_hash: data.file_hash,
                status: 'complete',
                report: data.report,
                timestamp: new Date(endTime),
                startTime: startTime,
                duration: duration,
                ml_prediction: data.ml_prediction,
                ml_prediction_time: data.ml_prediction_time,
                mime_type: data.mime_type,
                feature_importances: data.feature_importances,
                bat_analysis: data.bat_analysis,
              };
              setScanResults(prev => [newResult, ...prev].slice(0, 10));
            } else {
              const newScan: ScanResult = {
                id: scanId,
                filename: file.name,
                file_hash: data.file_hash,
                status: 'error',
                error: data.error || 'Upload or initial check failed',
                timestamp: new Date(),
                startTime: startTime,
                ml_prediction: data.ml_prediction,
                ml_prediction_time: data.ml_prediction_time,
                mime_type: data.mime_type,
                feature_importances: data.feature_importances,
                bat_analysis: data.bat_analysis,
              };
              setScanResults(prev => [newScan, ...prev].slice(0, 10));
            }
            
            // Clean up start time
            delete uploadStartTimes.current[file.name];
            
          } catch (error) {
            console.error(`Error uploading file ${file.name}:`, error);
            
            // Display error for this individual file
            const errorScan: ScanResult = {
              id: `error-${scanIdBase}`,
              filename: file.name,
              status: 'error',
              error: error instanceof Error ? error.message : "Upload failed",
              timestamp: new Date(),
              startTime: startTime
            };
            
            setScanResults(prev => [errorScan, ...prev].slice(0, 10));
            setCurrentScans(prev => prev.filter(s => s.id !== `temp-${scanIdBase}`));
            delete uploadStartTimes.current[file.name];
          }
        }
      } else {
        // Single file upload - similar flow but for just one file
        const file = files[0];
        formData.append('file', file);
        const startTime = uploadStartTimes.current[file.name] || uploadInitiationTime;
        const scanIdBase = `${file.name}-${startTime}`;

        // Create a temporary pending scan right away
        const tempScan: ScanResult = {
          id: `temp-${scanIdBase}`,
          filename: file.name,
          status: 'pending',
          timestamp: new Date(),
          startTime: startTime
        };
        
        // Show in queue immediately
        setCurrentScans(prev => [tempScan, ...prev]);
        
        console.log('Uploading file to: http://localhost:5000/upload');
        setProgress(30);

        const response = await fetch('http://localhost:5000/upload', {
          method: 'POST',
          body: formData,
        });

        setProgress(70);

        if (!response.ok) {
          throw new Error(`Upload failed: ${response.status} ${await response.text()}`);
        }

        const data = await response.json();
        console.log('Single upload result data:', data);
        const scanId = data.file_hash || data.analysis_id || scanIdBase;
        
        // Remove temporary scan
        setCurrentScans(prev => prev.filter(s => s.id !== `temp-${scanIdBase}`));

        // Immediately show ML result if available
        if (data.ml_prediction) {
          const mlResult: ScanResult = {
            id: `ml-${data.file_hash}`,
            filename: file.name,
            file_hash: data.file_hash,
            status: 'ml_only',
            timestamp: new Date(),
            startTime: uploadInitiationTime,
            ml_prediction: data.ml_prediction,
            ml_prediction_time: data.ml_prediction_time
          };
          setMlResults(prev => [mlResult, ...prev].slice(0, 10));
        }

        if (data.status === 'pending') {
          const newScan: ScanResult = {
            id: scanId,
            filename: file.name,
            file_hash: data.file_hash,
            analysis_id: data.analysis_id,
            status: 'pending',
            timestamp: new Date(),
            startTime: startTime,
            ml_prediction: data.ml_prediction,
            ml_prediction_time: data.ml_prediction_time,
            mime_type: data.mime_type,
            feature_importances: data.feature_importances,
            bat_analysis: data.bat_analysis,
          };
          setCurrentScans(prev => [newScan, ...prev]);
        } else if (data.status === 'complete') {
          const endTime = Date.now();
          const duration = endTime - startTime;
          const newResult: ScanResult = {
            id: scanId,
            filename: file.name,
            file_hash: data.file_hash,
            status: 'complete',
            report: data.report,
            timestamp: new Date(endTime),
            startTime: startTime,
            duration: duration,
            ml_prediction: data.ml_prediction,
            ml_prediction_time: data.ml_prediction_time,
            mime_type: data.mime_type,
            feature_importances: data.feature_importances,
            bat_analysis: data.bat_analysis,
          };
          setScanResults(prev => [newResult, ...prev].slice(0, 10));
        } else {
          const newScan: ScanResult = {
            id: scanId,
            filename: file.name,
            file_hash: data.file_hash,
            status: 'error',
            error: data.error || 'Upload or initial check failed',
            timestamp: new Date(),
            startTime: startTime,
            ml_prediction: data.ml_prediction,
            ml_prediction_time: data.ml_prediction_time,
            mime_type: data.mime_type,
            feature_importances: data.feature_importances,
            bat_analysis: data.bat_analysis,
          };
          setScanResults(prev => [newScan, ...prev]);
        }
        
        // Clean up start time
        delete uploadStartTimes.current[file.name];
      }

      setProgress(100);
    } catch (error) {
      console.error("Upload error:", error);
      setErrorMessage(error instanceof Error ? error.message : "An unknown error occurred during upload");
      // Clear start times on major error
      uploadStartTimes.current = {};
    } finally {
      setUploading(false);
      setProgress(0);
    }
  };

  const renderMlResults = () => (
    <Card className="p-5 bg-card/50 backdrop-blur border border-primary/20 mb-6">
      <h3 className="text-base font-semibold mb-4">ML Analysis Results</h3>
      {mlResults.length === 0 ? (
        <div className="text-center py-6 text-muted-foreground">
          <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
          <p className="text-sm">No ML predictions yet.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {mlResults.map((result) => {
            // Handle case where ml_prediction is an object
            const predictionText = typeof result.ml_prediction === 'string' 
              ? result.ml_prediction 
              : result.ml_prediction?.prediction || '';
              
            const isMalware = predictionText.toLowerCase().includes('malware');
            
            return (
              <div key={result.id} className="border border-primary/20 rounded-lg p-4 bg-primary/5 hover:bg-primary/10 transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {isMalware ?
                      <AlertTriangle className="w-4 h-4 text-destructive" /> :
                      <CheckCircle className="w-4 h-4 text-green-500" />
                    }
                    <p className="text-sm font-medium truncate">{result.filename}</p>
                  </div>
                  <Badge variant={isMalware ? "destructive" : "outline"}>
                    ML: {predictionText}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{format(result.timestamp, "MMM d, yyyy HH:mm")}</span>
                  {result.ml_prediction_time && (
                    <span className="flex items-center space-x-1">
                      <Shield className="w-3 h-3 text-primary" />
                      <span>ML: {result.ml_prediction_time.toFixed(3)}s</span>
                    </span>
                  )}
                </div>
                <div className="mt-3 pt-3 border-t border-primary/20 flex justify-between items-center">
                  <div className="flex items-center space-x-2">
                    <Info className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs">VirusTotal analysis in progress...</span>
                  </div>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );

  const isMalicious = (report: any): boolean => {
    if (!report?.data?.attributes) return false;
    const attributes = report.data.attributes;
    const stats = attributes.last_analysis_stats;

    // Check basic stats: malicious or suspicious count > 0
    if (stats && (stats.malicious > 0 || stats.suspicious > 0)) {
      return true;
    }

    // Check popular threat classification label (more reliable than category/name sometimes)
    if (attributes.popular_threat_classification?.suggested_threat_label) {
      const label = attributes.popular_threat_classification.suggested_threat_label.toLowerCase();
      // Consider common benign labels if necessary, otherwise assume any label is potentially risky
      if (label && label !== 'clean' && label !== 'benign' && label !== 'harmless') {
        return true;
      }
    }

    return false; // Default to not malicious if no clear indicators
  };

  const getDetectionRatio = (report: any): string => {
    if (!report?.data?.attributes?.last_analysis_stats) {
      // Attempt to count from results if stats missing
      const results = report?.data?.attributes?.last_analysis_results;
      if (!results) return "0/??";
      const engines = Object.keys(results);
      const malicious = engines.filter(e => results[e].category === 'malicious').length;
      const suspicious = engines.filter(e => results[e].category === 'suspicious').length;
      return `${malicious + suspicious}/${engines.length}`; // Or just malicious/total
    }

    const stats = report.data.attributes.last_analysis_stats;
    const totalEngines = (stats.harmless || 0) + (stats.type_unsupported || 0) + (stats.suspicious || 0) + (stats.confirmed_timeout || 0) + (stats.timeout || 0) + (stats.failure || 0) + (stats.malicious || 0) + (stats.undetected || 0);
    const maliciousCount = stats.malicious || 0;

    return `${maliciousCount}/${totalEngines || '??'}`; // Show total engines if available
  };

  // Helper to render threat tags - Adjusted slightly for styling
  const renderThreatTags = (report: any) => {
    if (!report?.data?.attributes?.popular_threat_classification) return null;

    const classification = report.data.attributes.popular_threat_classification;
    const categories = classification.popular_threat_category || [];
    const names = classification.popular_threat_name || [];
    const malicious = isMalicious(report);

    if (categories.length === 0 && names.length === 0) return null;

    return (
      <div className="space-y-3 pt-3 border-t border-border/20">
        {categories.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold mb-1.5 flex items-center">
              {malicious && <AlertTriangle className="w-3.5 h-3.5 mr-1 text-destructive" />}
              Popular Threat Categories:
            </h4>
            <div className="flex flex-wrap gap-1.5">
              {categories.map((category: { count: number; value: string }, index: number) => (
                <Badge key={`cat-${index}`} variant={malicious ? "destructive" : "secondary"} className="text-xs font-normal">
                  {category.value} ({category.count})
                </Badge>
              ))}
            </div>
          </div>
        )}

        {names.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold mb-1.5">Popular Threat Names:</h4>
            <div className="flex flex-wrap gap-1.5">
              {names.map((name: { count: number; value: string }, index: number) => (
                <Badge key={`name-${index}`} variant={malicious ? "destructive" : "secondary"} className="text-xs font-normal bg-purple-600/20 text-purple-300 border-purple-600/30 hover:bg-purple-600/30">
                  {name.value} ({name.count})
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* MIME Type Details (if detailed info is available) */}
        {report.mime_type && (
          <MimeTypeInfo mimeInfo={report.mime_type} />
        )}
      </div>
    );
  };

  // Helper to format duration
  const formatDuration = (milliseconds?: number): string | null => {
    if (typeof milliseconds !== 'number' || milliseconds < 0) return null;
    const seconds = milliseconds / 1000;
    if (seconds < 1) {
      return `${milliseconds} ms`;
    }
    return `${seconds.toFixed(1)} s`;
  };

  // Add helper function to render ML prediction badge
const renderMlPredictionBadge = (prediction?: string | {prediction: string, analysis_time?: number, feature_importances?: any}) => {
  if (!prediction) return null;

  // Handle the case where prediction is an object
  const predictionText = typeof prediction === 'string' 
    ? prediction 
    : prediction.prediction; // Extract the prediction string from the object
  
  if (!predictionText) return null;

  const isMalicious = predictionText.toLowerCase().includes('malware') ||
    predictionText.toLowerCase().includes('malicious');

  return (
    <Badge
      variant={isMalicious ? "destructive" : "outline"}
      className={`ml-2 ${isMalicious ? "bg-destructive/10" : "bg-green-500/10 text-green-500 border-green-500/30"}`}
    >
      ML: {predictionText}
    </Badge>
  );
};

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto p-6 space-y-8">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div className="space-y-1">
            <h1 className="text-4xl font-bold">Malware Scanner</h1>
            <p className="text-muted-foreground">
              Upload files to scan for malicious content using VirusTotal
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-primary" />
            <span className="text-sm font-medium text-muted-foreground">Powered by VirusTotal API</span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Upload Area & Queue */}
          <div className="lg:col-span-2 space-y-6">
            {/* Tabs for Single/Batch Upload */}
            <Tabs defaultValue="single" className="w-full">
              <TabsList className="grid w-full grid-cols-2 bg-card/50 backdrop-blur">
                <TabsTrigger value="single">Single File</TabsTrigger>
                <TabsTrigger value="batch">Batch Upload</TabsTrigger>
              </TabsList>

              {/* Single File Upload Area */}
              <TabsContent value="single" className="mt-6">
                <Card
                  className={cn(
                    "h-[300px] md:h-[400px] flex flex-col items-center justify-center border-2 border-dashed rounded-lg transition-colors relative group",
                    dragActive ? "border-primary bg-primary/5" : "border-border/50 hover:border-border"
                  )}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  {/* Subtle Glow Effect */}
                  <div className="absolute -inset-1 bg-gradient-to-r from-primary via-secondary to-primary rounded-lg blur-lg opacity-0 group-hover:opacity-20 transition duration-500 pointer-events-none"></div>
                  <div className="relative z-10 flex flex-col items-center justify-center text-center p-4">
                    <input
                      type="file"
                      className="hidden"
                      id="file-upload"
                      onChange={(e) => e.target.files && handleUpload(Array.from(e.target.files), false)}
                      disabled={uploading}
                    />
                    <label
                      htmlFor="file-upload"
                      className={cn("flex flex-col items-center justify-center cursor-pointer", uploading && "cursor-not-allowed opacity-50")}
                    >
                      <div className="p-3 bg-primary/10 rounded-full mb-4 border border-primary/20">
                        <Upload className="w-10 h-10 text-primary" />
                      </div>
                      <p className="text-lg font-medium">Drag & Drop or Click to Upload</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        Scan a single file with VirusTotal
                      </p>
                    </label>
                  </div>
                </Card>
              </TabsContent>

              {/* Batch File Upload Area */}
              <TabsContent value="batch" className="mt-6">
                <Card
                  className={cn(
                    "h-[300px] md:h-[400px] flex flex-col items-center justify-center border-2 border-dashed rounded-lg transition-colors relative group",
                    dragActive ? "border-secondary bg-secondary/5" : "border-border/50 hover:border-border"
                  )}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  <div className="absolute -inset-1 bg-gradient-to-r from-secondary via-primary to-secondary rounded-lg blur-lg opacity-0 group-hover:opacity-20 transition duration-500 pointer-events-none"></div>
                  <div className="relative z-10 flex flex-col items-center justify-center text-center p-4">
                    <input
                      type="file"
                      className="hidden"
                      id="batch-upload"
                      multiple
                      onChange={(e) => e.target.files && handleUpload(Array.from(e.target.files), true)}
                      disabled={uploading}
                    />
                    <label
                      htmlFor="batch-upload"
                      className={cn("flex flex-col items-center justify-center cursor-pointer", uploading && "cursor-not-allowed opacity-50")}
                    >
                      <div className="p-3 bg-secondary/10 rounded-full mb-4 border border-secondary/20">
                        <FileType className="w-10 h-10 text-secondary" />
                      </div>
                      <p className="text-lg font-medium">Batch File Upload</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        Upload multiple files for analysis
                      </p>
                    </label>
                  </div>
                </Card>
              </TabsContent>
            </Tabs>

            {/* Error Message Display */}
            {errorMessage && (
              <Card className="p-4 bg-destructive/10 text-destructive-foreground border border-destructive/30">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5" />
                  <p className="font-medium text-sm">{errorMessage}</p>
                </div>
              </Card>
            )}

            {/* Upload Progress Indicator */}
            {uploading && (
              <Card className="p-4 bg-card/50 backdrop-blur border border-border/50">
                <div className="flex items-center space-x-3 mb-2">
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                  <p className="text-sm font-medium">Processing upload...</p>
                </div>
                <Progress value={progress} className="h-1.5 bg-primary/20" />
              </Card>
            )}


            {/* Current Scan Queue */}
            {currentScans.length > 0 && !uploading && (
              <Card className="p-4 bg-card/50 backdrop-blur border border-border/50">
                <h3 className="text-base font-semibold mb-3">Analysis Queue</h3>
                <div className="space-y-2 max-h-[200px] overflow-y-auto pr-1">
                  {currentScans.map((scan) => (
                    <div key={scan.id} className="flex items-center space-x-2 p-2 rounded-md bg-background/50">
                      {scan.status === 'pending' && <Loader2 className="w-4 h-4 animate-spin text-primary flex-shrink-0" />}
                      {scan.status === 'error' && <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0" />}
                      {scan.status === 'failed' && <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />}

                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate" title={scan.filename}>{scan.filename}</p>
                        {scan.status === 'error' && <p className="text-xs text-destructive">{scan.error}</p>}
                        {scan.status === 'failed' && <p className="text-xs text-amber-500">{scan.error || 'Analysis failed'}</p>}
                        {scan.status === 'pending' && <p className="text-xs text-muted-foreground">Analyzing...</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}
            
            {/* Recent Scan Results Card - Updated UI */}
            <Card className="p-5 bg-card/50 backdrop-blur border border-border/50">
              <h3 className="text-base font-semibold mb-4">Recent Scan Results</h3>
              {scanResults.length === 0 ? (
                <div className="text-center py-6 text-muted-foreground">
                  <FileScan className="w-10 h-10 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No completed scans yet.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {scanResults.map((result) => {
                    const malicious = result.status === 'complete' && isMalicious(result.report);
                    const clean = result.status === 'complete' && !isMalicious(result.report);
                    const analysisFailed = result.status === 'failed' || result.status === 'error';
                    const formattedDuration = formatDuration(result.duration);

                    return (
                      <div key={result.id} className="border border-border/40 rounded-lg p-4 bg-background/30 hover:bg-background/50 transition-colors">
                        {/* Header Row: Filename and Status Badge */}
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2 min-w-0">
                            {malicious && <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0" />}
                            {clean && <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />}
                            {analysisFailed && <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />}
                            <p className="text-sm font-medium truncate" title={result.filename}>
                              {result.filename}
                            </p>
                          </div>

                          <div className="flex flex-wrap gap-2 justify-end">
                            {result.status === 'complete' && (
                              <Badge variant={malicious ? "destructive" : "secondary"}>
                                {malicious ? `Detected (${getDetectionRatio(result.report)})` : "Clean"}
                              </Badge>
                            )}
                            {analysisFailed && (
                              <Badge variant="outline" className="border-amber-500/50 text-amber-400">
                                Analysis Failed
                              </Badge>
                            )}
                            {renderMlPredictionBadge(result.ml_prediction)}
                          </div>
                        </div>

                        {/* Timestamp and Duration Row */}
                        <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
                          <span>{format(new Date(result.timestamp), "MMM d, yyyy HH:mm")}</span>
                          <div className="flex items-center space-x-3">
                            {formattedDuration && (
                              <span className="flex items-center space-x-1">
                                <Clock className="w-3 h-3" />
                                <span>VT: {formattedDuration}</span>
                              </span>
                            )}
                            {result.ml_prediction_time !== undefined && (
                              <span className="flex items-center space-x-1">
                                <Shield className="w-3 h-3 text-primary" />
                                <span>ML: {result.ml_prediction_time.toFixed(3)}s</span>
                              </span>
                            )}
                          </div>
                        </div>


                        {/* Detailed Threat Info (if applicable) */}
                        {result.status === 'complete' && (
                          <>
                            {renderThreatTags(result.report)}
                            
                            {/* MIME Type Details (if detailed info is available) */}
                            {result.mime_type && (
                              <MimeTypeInfo mimeInfo={result.mime_type} />
                            )}

                            {/* ML Prediction Details */}
                            {result.ml_prediction && (
                              <div className="mt-3 pt-3 border-t border-border/20">
                                <h4 className="text-xs font-semibold mb-1.5 flex items-center">
                                  <Shield className="w-3.5 h-3.5 mr-1 text-primary" />
                                  ML Analysis Result:
                                </h4>
                                <div className="flex items-center">
                                  <p className="text-sm">
                                    {typeof result.ml_prediction === 'string' 
                                      ? result.ml_prediction 
                                      : result.ml_prediction?.prediction}
                                    {result.ml_prediction_time !== undefined && (
                                      <span className="text-xs text-muted-foreground ml-2">
                                        (analyzed in {result.ml_prediction_time.toFixed(3)}s)
                                      </span>
                                    )}
                                  </p>
                                </div>
                              </div>
                            )}
                            
                            {/* Feature Importance Section */}
                            {result.feature_importances && result.feature_importances.length > 0 && (
                              <FeatureImportanceChart featureImportances={result.feature_importances} />
                            )}

                            {/* BAT File Analysis Summary */}
                            {result.bat_analysis && (
                              <div className="border-t border-border/20 pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium">BAT File Analysis</span>
                                  <Badge 
                                    variant={result.bat_analysis.prediction.toLowerCase().includes("malware") ? "destructive" : "secondary"}
                                    className="text-xs"
                                  >
                                    {result.bat_analysis.prediction}
                                  </Badge>
                                </div>
                                
                                {result.bat_analysis.suspicious_commands && result.bat_analysis.suspicious_commands.length > 0 && (
                                  <div className="text-xs text-destructive flex items-center mt-1">
                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                    <span>{result.bat_analysis.suspicious_commands.length} suspicious command{result.bat_analysis.suspicious_commands.length !== 1 ? 's' : ''} detected</span>
                                  </div>
                                )}
                                
                                {result.bat_analysis.known_patterns && result.bat_analysis.known_patterns.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {result.bat_analysis.known_patterns.slice(0, 3).map((pattern, idx) => (
                                      <Badge 
                                        key={idx} 
                                        variant="outline" 
                                        className="text-xs text-amber-500 border-amber-500/30 bg-amber-500/5"
                                      >
                                        {pattern}
                                      </Badge>
                                    ))}
                                    {result.bat_analysis.known_patterns.length > 3 && (
                                      <Badge variant="outline" className="text-xs">
                                        +{result.bat_analysis.known_patterns.length - 3} more
                                      </Badge>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}
                          </>
                        )}

                        {/* Show Error Message if scan failed */}
                        {analysisFailed && result.error && (
                          <p className="text-xs text-amber-400/80 mt-2">{result.error}</p>
                        )}

                        {/* View Report Button */}
                        {result.status === 'complete' && result.id && (
                          <div className="mt-3 pt-3 border-t border-border/20 flex justify-end">
                            <a
                              href={`/report/${result.id}`}
                              className="inline-flex items-center px-3 py-1.5 rounded-md text-xs font-medium 
                                bg-primary/10 text-primary hover:bg-primary/20 transition-colors
                                border border-primary/20 group"
                            >
                              <FileScan className="w-3.5 h-3.5 mr-1.5 group-hover:animate-pulse" />
                              View Detailed Report
                              <div className="ml-1 relative overflow-hidden w-4">
                                <span className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity duration-300 animate-bounce">→</span>
                              </div>
                            </a>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>
          </div> {/* End Left Column */}

          {/* Right Column: Scan Info & Results */}
          <div className="space-y-6">
            {/* Scan Information Card */}
            <Card className="p-5 bg-card/50 backdrop-blur border border-border/50">
              <h3 className="text-base font-semibold mb-4">Scan Information</h3>
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <FileScan className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">VirusTotal Integration</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Files are scanned using VirusTotal API across 70+ antivirus engines and security tools.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Shield className="w-4 h-4 text-purple-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">ML Prediction</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Files are analyzed with our machine learning model for rapid malware detection independent of VirusTotal results.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <FileType className="w-4 h-4 text-secondary mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">Supported File Types</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Executables (.exe), documents (.docx, .pdf), scripts (.bat, .ps1), archives, images, and more.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Upload className="w-4 h-4 text-accent mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="text-sm font-medium">File Size Limit</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Max 32MB per file via public API. Larger files may need premium API or different methods.
                    </p>
                  </div>
                </div>
              </div>
            </Card>


            {renderMlResults()}
            {/* Recent Scan Results Card - Updated UI */}

          </div> {/* End Right Column */}
        </div> {/* End Grid */}
      </div> {/* End Container */}
    </div> /* End Root Div */
  );
}