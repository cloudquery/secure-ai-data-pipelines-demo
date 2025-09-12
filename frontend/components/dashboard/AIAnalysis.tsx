/**
 * AI Analysis Dashboard Component
 */
import React, { useState, useEffect } from "react";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import {
  CpuChipIcon,
  PlayIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  SparklesIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronRightIcon,
} from "@heroicons/react/24/outline";
import apiClient from "../../lib/api/client";

interface AnalysisResult {
  analysis_id: string;
  message: string;
  resources_count: number;
  status: "running" | "completed" | "failed";
  analysis_breakdown?: {
    total_resources: number;
    providers: Array<{
      name: string;
      display_name: string;
      count: number;
      resource_types: Array<{
        type: string;
        count: number;
      }>;
    }>;
    resource_types: Array<{
      type: string;
      count: number;
    }>;
  };
  findings?: Array<{
    id: string;
    severity: string;
    finding_type: string;
    description: string;
    risk_score: number;
    remediation_status: string;
  }>;
  ai_metadata?: {
    ai_provider: string;
    analysis_timestamp: string;
    confidence_score: number;
  };
}

interface AnalysisHistory {
  id: string;
  timestamp: string;
  status: string;
  resources_analyzed: number;
  findings_count: number;
  ai_provider: string;
  findings?: Array<{
    id: string;
    severity: string;
    finding_type: string;
    description: string;
    risk_score: number;
    remediation_status: string;
  }>;
  ai_metadata?: {
    ai_provider: string;
    analysis_timestamp: string;
    confidence_score: number;
  };
}

export const AIAnalysis: React.FC = () => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(
    null
  );
  const [analysisHistory, setAnalysisHistory] = useState<AnalysisHistory[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [expandedHistoryId, setExpandedHistoryId] = useState<string | null>(
    null
  );
  const [showRawData, setShowRawData] = useState(false);

  useEffect(() => {
    fetchAnalysisHistory();
  }, []);

  const fetchAnalysisHistory = async () => {
    try {
      // Mock data for demonstration - in production this would come from the API
      setAnalysisHistory([
        {
          id: "1",
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          status: "completed",
          resources_analyzed: 778,
          findings_count: 45,
          ai_provider: "claude",
          findings: [
            {
              id: "h1-1",
              severity: "high",
              finding_type: "public_s3_bucket",
              description: "S3 bucket has public read access enabled",
              risk_score: 8.5,
              remediation_status: "open",
            },
            {
              id: "h1-2",
              severity: "medium",
              finding_type: "unencrypted_ebs",
              description: "EBS volume is not encrypted at rest",
              risk_score: 6.2,
              remediation_status: "open",
            },
            {
              id: "h1-3",
              severity: "critical",
              finding_type: "exposed_database",
              description: "RDS instance is publicly accessible",
              risk_score: 9.1,
              remediation_status: "open",
            },
            {
              id: "h1-4",
              severity: "high",
              finding_type: "overprivileged_iam",
              description: "IAM role has excessive permissions",
              risk_score: 7.8,
              remediation_status: "in_progress",
            },
            {
              id: "h1-5",
              severity: "medium",
              finding_type: "insecure_network",
              description: "Security group allows too broad access",
              risk_score: 6.1,
              remediation_status: "open",
            },
            {
              id: "h1-6",
              severity: "low",
              finding_type: "missing_monitoring",
              description: "Resource lacks proper monitoring",
              risk_score: 3.2,
              remediation_status: "open",
            },
            {
              id: "h1-7",
              severity: "critical",
              finding_type: "exposed_secrets",
              description: "Secrets exposed in environment variables",
              risk_score: 9.5,
              remediation_status: "open",
            },
            {
              id: "h1-8",
              severity: "high",
              finding_type: "weak_encryption",
              description: "Using weak encryption algorithm",
              risk_score: 5.8,
              remediation_status: "resolved",
            },
            {
              id: "h1-9",
              severity: "medium",
              finding_type: "public_gcp_bucket",
              description: "GCP storage bucket has public access",
              risk_score: 6.5,
              remediation_status: "open",
            },
            {
              id: "h1-10",
              severity: "high",
              finding_type: "unencrypted_azure_disk",
              description: "Azure disk is not encrypted",
              risk_score: 7.2,
              remediation_status: "open",
            },
            {
              id: "h1-11",
              severity: "critical",
              finding_type: "exposed_azure_sql",
              description: "Azure SQL server is publicly accessible",
              risk_score: 9.3,
              remediation_status: "open",
            },
            {
              id: "h1-12",
              severity: "medium",
              finding_type: "insecure_gcp_firewall",
              description: "GCP firewall rule allows unrestricted access",
              risk_score: 5.9,
              remediation_status: "open",
            },
          ],
          ai_metadata: {
            ai_provider: "claude",
            analysis_timestamp: new Date(
              Date.now() - 2 * 60 * 60 * 1000
            ).toISOString(),
            confidence_score: 0.92,
          },
        },
        {
          id: "2",
          timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          status: "completed",
          resources_analyzed: 38,
          findings_count: 8,
          ai_provider: "openai",
          findings: [
            {
              id: "h2-1",
              severity: "medium",
              finding_type: "weak_encryption",
              description: "Using weak encryption algorithm",
              risk_score: 5.8,
              remediation_status: "resolved",
            },
            {
              id: "h2-2",
              severity: "low",
              finding_type: "missing_monitoring",
              description: "Resource lacks proper monitoring",
              risk_score: 3.2,
              remediation_status: "open",
            },
          ],
          ai_metadata: {
            ai_provider: "openai",
            analysis_timestamp: new Date(
              Date.now() - 24 * 60 * 60 * 1000
            ).toISOString(),
            confidence_score: 0.87,
          },
        },
        {
          id: "3",
          timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
          status: "completed",
          resources_analyzed: 52,
          findings_count: 15,
          ai_provider: "claude",
          findings: [
            {
              id: "h3-1",
              severity: "high",
              finding_type: "overprivileged_iam",
              description: "IAM role has excessive permissions",
              risk_score: 7.8,
              remediation_status: "in_progress",
            },
            {
              id: "h3-2",
              severity: "critical",
              finding_type: "exposed_secrets",
              description: "Secrets exposed in environment variables",
              risk_score: 9.5,
              remediation_status: "open",
            },
            {
              id: "h3-3",
              severity: "medium",
              finding_type: "insecure_network",
              description: "Network security group allows too broad access",
              risk_score: 6.1,
              remediation_status: "open",
            },
          ],
          ai_metadata: {
            ai_provider: "claude",
            analysis_timestamp: new Date(
              Date.now() - 48 * 60 * 60 * 1000
            ).toISOString(),
            confidence_score: 0.94,
          },
        },
      ]);
    } catch (err: any) {
      console.error("Failed to fetch analysis history:", err);
    }
  };

  const runAnalysis = async () => {
    try {
      setIsAnalyzing(true);
      setError(null);

      const params: any = {};
      if (selectedProvider) {
        params.provider = selectedProvider;
      }

      const result = await apiClient.triggerSecurityAnalysis(params);

      setAnalysisResult({
        ...result,
        status: "running",
      });

      // Simulate analysis completion after a delay
      setTimeout(() => {
        setAnalysisResult({
          ...result,
          status: "completed",
          analysis_breakdown: {
            total_resources: 778,
            providers: [
              {
                name: "aws",
                display_name: "Amazon Web Services",
                count: 420,
                resource_types: [
                  { type: "ec2_instance", count: 45 },
                  { type: "s3_bucket", count: 23 },
                  { type: "rds_instance", count: 12 },
                  { type: "iam_role", count: 89 },
                  { type: "lambda_function", count: 34 },
                  { type: "vpc", count: 8 },
                  { type: "security_group", count: 67 },
                  { type: "ebs_volume", count: 142 },
                ],
              },
              {
                name: "gcp",
                display_name: "Google Cloud Platform",
                count: 258,
                resource_types: [
                  { type: "compute_instance", count: 32 },
                  { type: "storage_bucket", count: 18 },
                  { type: "sql_instance", count: 8 },
                  { type: "iam_service_account", count: 45 },
                  { type: "cloud_function", count: 23 },
                  { type: "compute_network", count: 12 },
                  { type: "compute_firewall", count: 34 },
                  { type: "compute_disk", count: 86 },
                ],
              },
              {
                name: "azure",
                display_name: "Microsoft Azure",
                count: 100,
                resource_types: [
                  { type: "virtual_machine", count: 15 },
                  { type: "storage_account", count: 8 },
                  { type: "sql_server", count: 5 },
                  { type: "service_principal", count: 12 },
                  { type: "function_app", count: 7 },
                  { type: "virtual_network", count: 6 },
                  { type: "network_security_group", count: 18 },
                  { type: "managed_disk", count: 29 },
                ],
              },
            ],
            resource_types: [
              { type: "ec2_instance", count: 45 },
              { type: "compute_instance", count: 32 },
              { type: "iam_role", count: 89 },
              { type: "iam_service_account", count: 45 },
              { type: "security_group", count: 67 },
              { type: "compute_firewall", count: 34 },
              { type: "ebs_volume", count: 142 },
              { type: "compute_disk", count: 86 },
              { type: "managed_disk", count: 29 },
              { type: "s3_bucket", count: 23 },
              { type: "storage_bucket", count: 18 },
              { type: "storage_account", count: 8 },
            ],
          },
          findings: [
            {
              id: "1",
              severity: "high",
              finding_type: "public_s3_bucket",
              description: "S3 bucket has public read access enabled",
              risk_score: 8.5,
              remediation_status: "open",
            },
            {
              id: "2",
              severity: "medium",
              finding_type: "unencrypted_ebs",
              description: "EBS volume is not encrypted at rest",
              risk_score: 6.2,
              remediation_status: "open",
            },
            {
              id: "3",
              severity: "critical",
              finding_type: "exposed_database",
              description: "RDS instance is publicly accessible",
              risk_score: 9.1,
              remediation_status: "open",
            },
            {
              id: "4",
              severity: "high",
              finding_type: "public_gcp_bucket",
              description: "GCP storage bucket has public access",
              risk_score: 6.5,
              remediation_status: "open",
            },
            {
              id: "5",
              severity: "critical",
              finding_type: "exposed_azure_sql",
              description: "Azure SQL server is publicly accessible",
              risk_score: 9.3,
              remediation_status: "open",
            },
            {
              id: "6",
              severity: "medium",
              finding_type: "insecure_gcp_firewall",
              description: "GCP firewall rule allows unrestricted access",
              risk_score: 5.9,
              remediation_status: "open",
            },
            {
              id: "7",
              severity: "high",
              finding_type: "unencrypted_azure_disk",
              description: "Azure disk is not encrypted",
              risk_score: 7.2,
              remediation_status: "open",
            },
            {
              id: "8",
              severity: "high",
              finding_type: "overprivileged_iam",
              description: "IAM role has excessive permissions",
              risk_score: 7.8,
              remediation_status: "in_progress",
            },
          ],
          ai_metadata: {
            ai_provider: "claude",
            analysis_timestamp: new Date().toISOString(),
            confidence_score: 0.92,
            model_version: "claude-3-sonnet-20240229",
            analysis_duration_ms: 15420,
            tokens_used: 2847,
            raw_ai_response: {
              risk_score: 7.8,
              severity: "high",
              vulnerabilities: [
                {
                  type: "public_access",
                  description: "Resource has public access enabled",
                  impact: "Potential data exposure",
                  attack_vectors: [
                    "Direct internet access",
                    "Data exfiltration",
                  ],
                },
                {
                  type: "encryption_disabled",
                  description: "Resource does not have encryption enabled",
                  impact: "Data stored in plaintext",
                  attack_vectors: ["Data breach", "Compliance violation"],
                },
              ],
              recommendations: [
                {
                  action: "Enable encryption at rest",
                  priority: "high",
                  effort: "medium",
                  compliance_benefit: ["PCI DSS", "SOC 2"],
                },
                {
                  action: "Restrict public access",
                  priority: "critical",
                  effort: "low",
                  compliance_benefit: ["PCI DSS", "SOC 2", "ISO 27001"],
                },
              ],
              compliance_violations: [
                {
                  framework: "PCI DSS",
                  control: "3.4",
                  description: "Encryption not enabled for sensitive data",
                },
                {
                  framework: "SOC 2",
                  control: "CC6.1",
                  description:
                    "Public access violates access control requirements",
                },
              ],
            },
          },
        });
        setIsAnalyzing(false);
      }, 3000);
    } catch (err: any) {
      setError(err.message || "Failed to start analysis");
      setIsAnalyzing(false);
    }
  };

  const toggleHistoryExpansion = (historyId: string) => {
    setExpandedHistoryId(expandedHistoryId === historyId ? null : historyId);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-100 text-red-800";
      case "high":
        return "bg-orange-100 text-orange-800";
      case "medium":
        return "bg-yellow-100 text-yellow-800";
      case "low":
        return "bg-green-100 text-green-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case "running":
        return <ArrowPathIcon className="w-5 h-5 text-blue-500 animate-spin" />;
      case "failed":
        return <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <ClockIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Analysis Controls */}
      <Card
        title="AI-Powered Security Analysis"
        subtitle="Run comprehensive security analysis using AI"
      >
        <div className="space-y-4">
          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Cloud Provider (Optional)
              </label>
              <select
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Providers</option>
                <option value="aws">AWS</option>
                <option value="gcp">Google Cloud</option>
                <option value="azure">Azure</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                onClick={runAnalysis}
                disabled={isAnalyzing}
                className="flex items-center space-x-2 px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isAnalyzing ? (
                  <ArrowPathIcon className="w-5 h-5 animate-spin" />
                ) : (
                  <PlayIcon className="w-5 h-5" />
                )}
                <span>{isAnalyzing ? "Analyzing..." : "Run AI Analysis"}</span>
              </button>
            </div>
          </div>

          {error && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-md">
              <div className="flex items-center">
                <ExclamationTriangleIcon className="w-5 h-5 text-red-500 mr-2" />
                <span className="text-red-700">{error}</span>
              </div>
            </div>
          )}

          <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
            <div className="flex items-start">
              <SparklesIcon className="w-5 h-5 text-blue-500 mr-2 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-blue-900 mb-1">
                  Multi-Cloud AI Analysis Features
                </h4>
                <ul className="text-sm text-blue-700 space-y-1">
                  <li>
                    • GPT-4 and Claude-powered security assessment across AWS,
                    GCP, and Azure
                  </li>
                  <li>• Automated risk scoring and severity classification</li>
                  <li>
                    • Compliance framework evaluation (PCI DSS, SOC 2, ISO
                    27001)
                  </li>
                  <li>
                    • Attack path detection and privilege escalation analysis
                  </li>
                  <li>• Automated remediation recommendations</li>
                  <li>
                    • Comprehensive resource breakdown by provider and type
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Analysis Results */}
      {analysisResult && (
        <Card
          title="Analysis Results"
          subtitle={`Analysis ID: ${analysisResult.analysis_id}`}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {getStatusIcon(analysisResult.status)}
                <span className="font-medium">
                  {analysisResult.status === "running"
                    ? "Analysis in Progress"
                    : "Analysis Complete"}
                </span>
              </div>
              <div className="text-sm text-gray-600">
                {analysisResult.resources_count} resources analyzed
              </div>
            </div>

            {/* Analysis Breakdown */}
            {analysisResult.analysis_breakdown && (
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-3">
                  Analysis Scope Breakdown
                </h4>

                {/* Provider Breakdown */}
                <div className="mb-4">
                  <h5 className="text-sm font-medium text-gray-700 mb-2">
                    Cloud Providers (
                    {analysisResult.analysis_breakdown.providers.length})
                  </h5>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {analysisResult.analysis_breakdown.providers.map(
                      (provider) => (
                        <div
                          key={provider.name}
                          className="bg-white rounded border p-3"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-medium text-gray-900">
                              {provider.display_name}
                            </span>
                            <Badge variant="info" size="sm">
                              {provider.count} resources
                            </Badge>
                          </div>
                          <div className="text-xs text-gray-600">
                            <div className="font-medium mb-1">
                              Resource Types:
                            </div>
                            <div className="space-y-1">
                              {provider.resource_types.slice(0, 3).map((rt) => (
                                <div
                                  key={rt.type}
                                  className="flex justify-between"
                                >
                                  <span>{rt.type.replace(/_/g, " ")}</span>
                                  <span>{rt.count}</span>
                                </div>
                              ))}
                              {provider.resource_types.length > 3 && (
                                <div className="text-gray-500">
                                  +{provider.resource_types.length - 3} more...
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )
                    )}
                  </div>
                </div>

                {/* Top Resource Types */}
                <div>
                  <h5 className="text-sm font-medium text-gray-700 mb-2">
                    Top Resource Types
                  </h5>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {analysisResult.analysis_breakdown.resource_types
                      .slice(0, 8)
                      .map((rt) => (
                        <div
                          key={rt.type}
                          className="bg-white rounded border p-2 text-center"
                        >
                          <div className="text-sm font-medium text-gray-900">
                            {rt.count}
                          </div>
                          <div className="text-xs text-gray-600">
                            {rt.type.replace(/_/g, " ")}
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            )}

            {analysisResult.status === "completed" &&
              analysisResult.findings && (
                <div className="space-y-3">
                  <h4 className="font-medium text-gray-900">
                    Security Findings
                  </h4>
                  <div className="space-y-2">
                    {analysisResult.findings.map((finding) => (
                      <div
                        key={finding.id}
                        className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                      >
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <Badge
                              className={getSeverityColor(finding.severity)}
                            >
                              {finding.severity.toUpperCase()}
                            </Badge>
                            <span className="text-sm font-medium text-gray-900">
                              {finding.finding_type.replace("_", " ")}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600">
                            {finding.description}
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-medium text-gray-900">
                            Risk: {finding.risk_score}/10
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {analysisResult.ai_metadata && (
                    <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-600">AI Provider:</span>
                        <span className="font-medium">
                          {analysisResult.ai_metadata.ai_provider.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-sm mt-1">
                        <span className="text-gray-600">Confidence Score:</span>
                        <span className="font-medium">
                          {(
                            analysisResult.ai_metadata.confidence_score * 100
                          ).toFixed(1)}
                          %
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
          </div>
        </Card>
      )}

      {/* Analysis History */}
      <Card title="Analysis History" subtitle="Recent AI security analyses">
        <div className="space-y-3">
          {analysisHistory.map((analysis) => (
            <div key={analysis.id} className="bg-gray-50 rounded-lg">
              {/* History Item Header - Clickable */}
              <div
                className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-100 transition-colors"
                onClick={() => toggleHistoryExpansion(analysis.id)}
              >
                <div className="flex items-center space-x-3">
                  {expandedHistoryId === analysis.id ? (
                    <ChevronDownIcon className="w-4 h-4 text-gray-500" />
                  ) : (
                    <ChevronRightIcon className="w-4 h-4 text-gray-500" />
                  )}
                  {getStatusIcon(analysis.status)}
                  <div>
                    <div className="text-sm font-medium text-gray-900">
                      {new Date(analysis.timestamp).toLocaleString()}
                    </div>
                    <div className="text-xs text-gray-600">
                      {analysis.resources_analyzed} resources •{" "}
                      {analysis.findings_count} findings
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="info" size="sm">
                    {analysis.ai_provider.toUpperCase()}
                  </Badge>
                  <Badge
                    className={
                      analysis.status === "completed"
                        ? "bg-green-100 text-green-800"
                        : "bg-gray-100 text-gray-800"
                    }
                  >
                    {analysis.status}
                  </Badge>
                </div>
              </div>

              {/* Expanded Content */}
              {expandedHistoryId === analysis.id && analysis.findings && (
                <div className="px-3 pb-3 border-t border-gray-200">
                  <div className="pt-3 space-y-3">
                    <h4 className="font-medium text-gray-900 text-sm">
                      Security Findings
                    </h4>
                    <div className="space-y-2">
                      {analysis.findings.map((finding) => (
                        <div
                          key={finding.id}
                          className="flex items-center justify-between p-2 bg-white rounded border"
                        >
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              <Badge
                                className={getSeverityColor(finding.severity)}
                                size="sm"
                              >
                                {finding.severity.toUpperCase()}
                              </Badge>
                              <span className="text-xs font-medium text-gray-900">
                                {finding.finding_type.replace("_", " ")}
                              </span>
                            </div>
                            <p className="text-xs text-gray-600">
                              {finding.description}
                            </p>
                          </div>
                          <div className="text-right">
                            <div className="text-xs font-medium text-gray-900">
                              Risk: {finding.risk_score}/10
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* AI Metadata */}
                    {analysis.ai_metadata && (
                      <div className="mt-3 p-2 bg-white rounded border">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-gray-600">AI Provider:</span>
                          <span className="font-medium">
                            {analysis.ai_metadata.ai_provider.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-xs mt-1">
                          <span className="text-gray-600">
                            Confidence Score:
                          </span>
                          <span className="font-medium">
                            {(
                              analysis.ai_metadata.confidence_score * 100
                            ).toFixed(1)}
                            %
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Raw AI Data Section */}
      {analysisResult && analysisResult.status === "completed" && (
        <Card
          title="Raw AI Analysis Data"
          subtitle="Expand to view detailed AI provider response"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <SparklesIcon className="w-5 h-5 text-blue-500" />
                <span className="text-sm font-medium text-gray-700">
                  AI Provider Response Data
                </span>
              </div>
              <button
                onClick={() => setShowRawData(!showRawData)}
                className="flex items-center space-x-1 px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                {showRawData ? (
                  <ChevronDownIcon className="w-4 h-4" />
                ) : (
                  <ChevronRightIcon className="w-4 h-4" />
                )}
                <span>{showRawData ? "Hide" : "Show"} Raw Data</span>
              </button>
            </div>

            {showRawData && (
              <div className="space-y-4">
                {/* AI Metadata */}
                {analysisResult.ai_metadata && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h5 className="font-medium text-gray-900 mb-2">
                      AI Metadata
                    </h5>
                    <pre className="text-xs text-gray-700 bg-white p-3 rounded border overflow-x-auto">
                      {JSON.stringify(analysisResult.ai_metadata, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Analysis Breakdown */}
                {analysisResult.analysis_breakdown && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h5 className="font-medium text-gray-900 mb-2">
                      Analysis Breakdown
                    </h5>
                    <pre className="text-xs text-gray-700 bg-white p-3 rounded border overflow-x-auto">
                      {JSON.stringify(
                        analysisResult.analysis_breakdown,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}

                {/* Findings Data */}
                {analysisResult.findings && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h5 className="font-medium text-gray-900 mb-2">
                      Security Findings
                    </h5>
                    <pre className="text-xs text-gray-700 bg-white p-3 rounded border overflow-x-auto">
                      {JSON.stringify(analysisResult.findings, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Complete Analysis Result */}
                <div className="bg-gray-50 rounded-lg p-4">
                  <h5 className="font-medium text-gray-900 mb-2">
                    Complete Analysis Result
                  </h5>
                  <pre className="text-xs text-gray-700 bg-white p-3 rounded border overflow-x-auto max-h-96 overflow-y-auto">
                    {JSON.stringify(analysisResult, null, 2)}
                  </pre>
                </div>

                {/* Technical Info */}
                <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                  <div className="flex items-start">
                    <ExclamationTriangleIcon className="w-5 h-5 text-blue-500 mr-2 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-medium text-blue-900 mb-1">
                        Raw Data Information
                      </h4>
                      <ul className="text-sm text-blue-700 space-y-1">
                        <li>
                          • This data shows the complete response from the AI
                          provider
                        </li>
                        <li>
                          • Useful for debugging analysis results and
                          understanding AI reasoning
                        </li>
                        <li>
                          • Includes confidence scores, timestamps, and detailed
                          findings
                        </li>
                        <li>
                          • Data structure may vary between different AI
                          providers (OpenAI vs Claude)
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};
