export interface DynamicReport {
  hash?: string;
  verdict?: string;
  threat_score?: number;
  scan_time?: number;
  filename?: string;
  classification?: string[];
  signatures?: {
    description: string;
    severity: string;
    mitre_tactics?: string[];
    detail?: string;
  }[];
  scanners_v2?: Record<string, any>;
  network?: {
    connections: {
      destination_ip: string;
      port: number;
      protocol: string;
      malicious: boolean;
      url?: string;
    }[];
  };
  filesystem?: {
    path: string;
    action: string;
    malicious: boolean;
  }[];
  processes?: {
    name: string;
    pid: number;
    command_line?: string;
    malicious: boolean;
  }[];
  environment?: {
    os: string;
    architecture: string;
  };
  mime_type?: {
    mime_type: string;
    mime_category: string;
    mime_description: string;
  };
}

export interface FeatureImportance {
  feature: string;
  importance: number;
  description: string;
}

export interface ScanResult {
  file_hash: string;
  report: any;
  status: string;
  ml_prediction: string;
  ml_prediction_time: number;
  feature_importances?: FeatureImportance[];
  mime_type?: {
    mime_type: string;
    mime_category: string;
    mime_description: string;
  };
} 