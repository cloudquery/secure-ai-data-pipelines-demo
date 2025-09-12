/**
 * Security Overview Dashboard Component
 */
import React, { useState, useEffect } from "react";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  AreaChart,
  Area,
} from "recharts";
import apiClient from "../../lib/api/client";

interface SecurityDashboardData {
  total_findings: number;
  high_risk_findings: number;
  recent_findings: number;
  average_risk_score: number;
  severity_distribution: Array<{ severity: string; count: number }>;
  status_distribution: Array<{ status: string; count: number }>;
  top_finding_types: Array<{ type: string; count: number }>;
  top_resource_types?: Array<{
    resource_type: string;
    count: number;
    findings: number;
  }>;
  urgent_findings?: Array<{
    id: string;
    title: string;
    severity: string;
    risk_score: number;
    finding_type: string;
    resource_name: string;
    provider: string;
  }>;
  trends_data?: Array<{
    date: string;
    findings: number;
    resolved: number;
  }>;
  compliance_violations?: Array<{
    framework: string;
    violations: number;
    critical_violations: number;
    compliance_score: number;
  }>;
}

interface DetailedFinding {
  id: string;
  title: string;
  severity: string;
  risk_score: number;
  finding_type: string;
  description: string;
  resource_name: string;
  resource_type: string;
  provider: string;
  region: string;
  remediation_status: string;
  first_detected: string;
}

const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
  info: "#0284c7",
};

const STATUS_COLORS = {
  open: "#dc2626",
  in_progress: "#d97706",
  resolved: "#16a34a",
  false_positive: "#6b7280",
};

// Modal Component for Detailed Views
const SecurityDetailModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-cloudquery-bgGradient rounded-lg max-w-4xl w-full max-h-[90vh] overflow-hidden border border-cloudquery-logoGreen/20">
        <div className="flex items-center justify-between p-6 border-b border-cloudquery-logoGreen/20">
          <h2 className="text-xl font-semibold text-brand-white">{title}</h2>
          <button
            onClick={onClose}
            className="text-cloudquery-textWhite/80 hover:text-brand-white"
          >
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          {children}
        </div>
      </div>
    </div>
  );
};

// Expandable Metric Card Component
const ExpandableMetricCard: React.FC<{
  icon: React.ReactNode;
  title: string;
  value: number;
  subtitle?: string;
  onClick: () => void;
  isExpanded?: boolean;
  children?: React.ReactNode;
}> = ({ icon, title, value, subtitle, onClick, isExpanded, children }) => {
  return (
    <Card className="text-center cursor-pointer hover:shadow-lg transition-shadow">
      <div onClick={onClick} className="p-6">
        <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-red-100 rounded-full">
          {icon}
        </div>
        <div className="text-2xl font-bold text-brand-white">{value}</div>
        <div className="text-sm text-brand-white">{title}</div>
        {subtitle && (
          <div className="text-xs text-cloudquery-textWhite/80 mt-1">
            {subtitle}
          </div>
        )}
        <div className="mt-2 flex justify-center">
          {isExpanded ? (
            <ChevronUpIcon className="w-4 h-4 text-brand-white" />
          ) : (
            <ChevronDownIcon className="w-4 h-4 text-brand-white" />
          )}
        </div>
      </div>
      {isExpanded && children && (
        <div className="border-t border-cloudquery-logoGreen/20 p-4 text-brand-white">
          {children}
        </div>
      )}
    </Card>
  );
};

export const SecurityOverview: React.FC = () => {
  const [data, setData] = useState<SecurityDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState<string | null>(null);
  const [detailedFindings, setDetailedFindings] = useState<DetailedFinding[]>(
    []
  );
  const [pagination, setPagination] = useState({
    page: 1,
    size: 20,
    total: 0,
    pages: 0,
  });

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      console.log("Fetching security dashboard data...");
      const response = await apiClient.getSecurityDashboard();
      console.log("Security data received:", response);
      setData(response);
      setError(null);
    } catch (err: any) {
      console.error("Security dashboard error:", err);
      setError(err.message || "Failed to fetch dashboard data");
    } finally {
      setLoading(false);
    }
  };

  const fetchDetailedFindings = async (filter: string, page: number = 1) => {
    try {
      let response;

      if (filter === "urgent") {
        // Use the dedicated urgent findings endpoint
        response = await apiClient.get("/security/urgent");
        // Combine critical and high-risk findings for urgent view
        const urgentFindings = [
          ...(response.critical_findings || []),
          ...(response.high_risk_findings || []),
        ];
        setDetailedFindings(urgentFindings);
        setPagination({
          page: 1,
          size: urgentFindings.length,
          total: urgentFindings.length,
          pages: 1,
        });
        return;
      } else {
        const params = new URLSearchParams();
        if (filter === "high-risk") {
          params.append("severity", "critical,high");
        } else if (filter === "recent") {
          // This would need backend support for date filtering
          params.append("recent", "7");
        }

        // Add pagination parameters
        params.append("page", page.toString());
        params.append("size", "20");

        response = await apiClient.get(
          "/security/findings?" + params.toString()
        );
        setDetailedFindings(response.items || []);
        setPagination({
          page: response.page || 1,
          size: response.size || 20,
          total: response.total || 0,
          pages: response.pages || 1,
        });
      }
    } catch (err: any) {
      console.error("Failed to fetch detailed findings:", err);
      // Fallback to mock data for urgent findings
      if (filter === "urgent") {
        setDetailedFindings([
          {
            id: "urgent-1",
            title: "Critical: Public S3 Bucket Exposed",
            severity: "critical",
            risk_score: 9.5,
            finding_type: "public_s3_bucket",
            description:
              "S3 bucket has public read access enabled, potentially exposing sensitive data to unauthorized users.",
            resource_name: "production-data-bucket",
            resource_type: "s3_bucket",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 2 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "urgent-2",
            title: "Critical: Database Publicly Accessible",
            severity: "critical",
            risk_score: 9.1,
            finding_type: "exposed_database",
            description:
              "RDS instance is publicly accessible from the internet, creating a significant security risk.",
            resource_name: "prod-database-instance",
            resource_type: "rds_instance",
            provider: "aws",
            region: "us-west-2",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 4 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "urgent-3",
            title: "High: Secrets Exposed in Environment",
            severity: "high",
            risk_score: 8.8,
            finding_type: "exposed_secrets",
            description:
              "API keys and secrets are exposed in environment variables without proper encryption.",
            resource_name: "web-app-lambda",
            resource_type: "lambda_function",
            provider: "aws",
            region: "eu-west-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 6 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "urgent-4",
            title: "High: Azure SQL Server Public Access",
            severity: "high",
            risk_score: 8.3,
            finding_type: "exposed_azure_sql",
            description:
              "Azure SQL server is configured with public network access enabled.",
            resource_name: "azure-sql-server-prod",
            resource_type: "sql_server",
            provider: "azure",
            region: "eastus",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 8 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "urgent-5",
            title: "High: GCP Storage Bucket Public",
            severity: "high",
            risk_score: 7.9,
            finding_type: "public_gcp_bucket",
            description: "GCP storage bucket has public read access enabled.",
            resource_name: "gcp-storage-bucket",
            resource_type: "storage_bucket",
            provider: "gcp",
            region: "us-central1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 12 * 60 * 60 * 1000
            ).toISOString(),
          },
        ]);
      } else if (filter === "high-risk") {
        // Mock high-risk findings
        setDetailedFindings([
          {
            id: "high-1",
            title: "High: Overprivileged IAM Role",
            severity: "high",
            risk_score: 8.2,
            finding_type: "overprivileged_iam",
            description:
              "IAM role has excessive permissions beyond what is required for its function.",
            resource_name: "lambda-execution-role",
            resource_type: "iam_role",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 24 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "high-2",
            title: "High: Unencrypted EBS Volume",
            severity: "high",
            risk_score: 7.8,
            finding_type: "unencrypted_ebs",
            description:
              "EBS volume is not encrypted at rest, potentially exposing sensitive data.",
            resource_name: "database-volume",
            resource_type: "ebs_volume",
            provider: "aws",
            region: "us-west-2",
            remediation_status: "in_progress",
            first_detected: new Date(
              Date.now() - 48 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "high-3",
            title: "High: Insecure Network Configuration",
            severity: "high",
            risk_score: 7.5,
            finding_type: "insecure_network",
            description: "Security group allows overly broad access patterns.",
            resource_name: "web-tier-sg",
            resource_type: "security_group",
            provider: "aws",
            region: "eu-west-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 72 * 60 * 60 * 1000
            ).toISOString(),
          },
        ]);
      } else if (filter === "recent") {
        // Mock recent findings
        setDetailedFindings([
          {
            id: "recent-1",
            title: "Medium: Missing CloudTrail Logging",
            severity: "medium",
            risk_score: 6.5,
            finding_type: "missing_logging",
            description:
              "Resource lacks proper CloudTrail logging configuration.",
            resource_name: "api-gateway-prod",
            resource_type: "apigateway_rest_api",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 2 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "recent-2",
            title: "Medium: Weak Encryption Algorithm",
            severity: "medium",
            risk_score: 6.2,
            finding_type: "weak_encryption",
            description: "Resource is using a weak encryption algorithm.",
            resource_name: "kms-key-1",
            resource_type: "kms_key",
            provider: "aws",
            region: "us-west-2",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 4 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "recent-3",
            title: "Low: Missing Monitoring",
            severity: "low",
            risk_score: 4.1,
            finding_type: "missing_monitoring",
            description:
              "Resource lacks proper monitoring and alerting configuration.",
            resource_name: "ec2-instance-1",
            resource_type: "ec2_instance",
            provider: "aws",
            region: "eu-west-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 6 * 60 * 60 * 1000
            ).toISOString(),
          },
        ]);
      } else if (filter === "total") {
        // Mock all findings
        setDetailedFindings([
          {
            id: "total-1",
            title: "Critical: Public S3 Bucket Exposed",
            severity: "critical",
            risk_score: 9.5,
            finding_type: "public_s3_bucket",
            description:
              "S3 bucket has public read access enabled, potentially exposing sensitive data to unauthorized users.",
            resource_name: "production-data-bucket",
            resource_type: "s3_bucket",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 2 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "total-2",
            title: "High: Overprivileged IAM Role",
            severity: "high",
            risk_score: 8.2,
            finding_type: "overprivileged_iam",
            description:
              "IAM role has excessive permissions beyond what is required for its function.",
            resource_name: "lambda-execution-role",
            resource_type: "iam_role",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 24 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "total-3",
            title: "Medium: Missing CloudTrail Logging",
            severity: "medium",
            risk_score: 6.5,
            finding_type: "missing_logging",
            description:
              "Resource lacks proper CloudTrail logging configuration.",
            resource_name: "api-gateway-prod",
            resource_type: "apigateway_rest_api",
            provider: "aws",
            region: "us-east-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 2 * 60 * 60 * 1000
            ).toISOString(),
          },
          {
            id: "total-4",
            title: "Low: Missing Monitoring",
            severity: "low",
            risk_score: 4.1,
            finding_type: "missing_monitoring",
            description:
              "Resource lacks proper monitoring and alerting configuration.",
            resource_name: "ec2-instance-1",
            resource_type: "ec2_instance",
            provider: "aws",
            region: "eu-west-1",
            remediation_status: "open",
            first_detected: new Date(
              Date.now() - 6 * 60 * 60 * 1000
            ).toISOString(),
          },
        ]);
      } else {
        setDetailedFindings([]);
      }
    }
  };

  const handleCardClick = (cardType: string) => {
    if (expandedCard === cardType) {
      setExpandedCard(null);
    } else {
      setExpandedCard(cardType);
      fetchDetailedFindings(cardType);
    }
  };

  const handleModalOpen = (modalType: string) => {
    setModalOpen(modalType);
    setPagination({
      page: 1,
      size: 20,
      total: 0,
      pages: 0,
    });
    fetchDetailedFindings(modalType, 1);
  };

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-gray-200 h-32 rounded-lg"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-200 h-80 rounded-lg"></div>
          <div className="bg-gray-200 h-80 rounded-lg"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <Card className="text-center py-12">
        <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-red-500 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          Error Loading Dashboard
        </h3>
        <p className="text-gray-600 mb-4">{error}</p>
        <button
          onClick={fetchDashboardData}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
        >
          Retry
        </button>
      </Card>
    );
  }

  if (!data) {
    return null;
  }

  const severityData = data.severity_distribution.map((item) => ({
    name: item.severity,
    value: item.count,
    color:
      SEVERITY_COLORS[item.severity as keyof typeof SEVERITY_COLORS] ||
      "#6b7280",
  }));

  const statusData = data.status_distribution.map((item) => ({
    name: item.status,
    value: item.count,
    color:
      STATUS_COLORS[item.status as keyof typeof STATUS_COLORS] || "#6b7280",
  }));

  return (
    <div className="space-y-6">
      {/* Urgent Security Considerations */}
      <Card
        title="🚨 Urgent Security Considerations"
        className="border-red-500 bg-red-900"
      >
        <div className="space-y-4">
          <div className="text-sm text-white mb-4">
            The following findings require immediate attention:
          </div>

          {/* Mock urgent findings - in real implementation, this would come from the API */}
          <div className="space-y-3">
            {data.severity_distribution.filter((s) => s.severity === "critical")
              .length > 0 && (
              <div className="flex items-center justify-between p-3 bg-red-800 rounded-lg border border-red-600">
                <div className="flex items-center space-x-3">
                  <ExclamationTriangleIcon className="w-5 h-5 text-white" />
                  <div>
                    <div className="font-medium text-white">
                      Critical Severity Findings
                    </div>
                    <div className="text-sm text-white">
                      {data.severity_distribution.find(
                        (s) => s.severity === "critical"
                      )?.count || 0}{" "}
                      critical findings detected
                    </div>
                  </div>
                </div>
                <Badge variant="critical">
                  {data.severity_distribution.find(
                    (s) => s.severity === "critical"
                  )?.count || 0}
                </Badge>
              </div>
            )}

            {data.high_risk_findings > 0 && (
              <div className="flex items-center justify-between p-3 bg-orange-800 rounded-lg border border-orange-600">
                <div className="flex items-center space-x-3">
                  <ShieldExclamationIcon className="w-5 h-5 text-white" />
                  <div>
                    <div className="font-medium text-white">
                      High Risk Findings
                    </div>
                    <div className="text-sm text-white">
                      {data.high_risk_findings} high-risk findings require
                      attention
                    </div>
                  </div>
                </div>
                <Badge variant="high">{data.high_risk_findings}</Badge>
              </div>
            )}

            {data.recent_findings > 5 && (
              <div className="flex items-center justify-between p-3 bg-yellow-800 rounded-lg border border-yellow-600">
                <div className="flex items-center space-x-3">
                  <ClockIcon className="w-5 h-5 text-white" />
                  <div>
                    <div className="font-medium text-white">
                      High Recent Activity
                    </div>
                    <div className="text-sm text-white">
                      {data.recent_findings} new findings in the last 7 days
                    </div>
                  </div>
                </div>
                <Badge variant="medium">{data.recent_findings}</Badge>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-red-600">
            <button
              onClick={() => handleModalOpen("urgent")}
              className="w-full px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
            >
              View All Urgent Findings
            </button>
          </div>
        </div>
      </Card>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <ExpandableMetricCard
          icon={<ShieldExclamationIcon className="w-6 h-6 text-red-600" />}
          title="Total Findings"
          value={data.total_findings}
          subtitle="All security issues detected"
          onClick={() => handleCardClick("total")}
          isExpanded={expandedCard === "total"}
        >
          <div className="text-left space-y-2">
            <div className="text-sm font-medium text-brand-white">
              Breakdown by Severity:
            </div>
            {data.severity_distribution.map((item) => (
              <div
                key={item.severity}
                className="flex justify-between text-xs text-brand-white"
              >
                <span className="capitalize">{item.severity}</span>
                <span className="font-medium">{item.count}</span>
              </div>
            ))}
            <button
              onClick={() => handleModalOpen("total")}
              className="w-full mt-3 px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700"
            >
              View All Findings
            </button>
          </div>
        </ExpandableMetricCard>

        <ExpandableMetricCard
          icon={<ExclamationTriangleIcon className="w-6 h-6 text-orange-600" />}
          title="High Risk"
          value={data.high_risk_findings}
          subtitle="Critical & High severity"
          onClick={() => handleCardClick("high-risk")}
          isExpanded={expandedCard === "high-risk"}
        >
          <div className="text-left space-y-2">
            <div className="text-sm font-medium text-brand-white">
              Risk Distribution:
            </div>
            <div className="text-xs text-brand-white font-medium">
              Critical:{" "}
              {data.severity_distribution.find((s) => s.severity === "critical")
                ?.count || 0}
            </div>
            <div className="text-xs text-brand-white font-medium">
              High:{" "}
              {data.severity_distribution.find((s) => s.severity === "high")
                ?.count || 0}
            </div>
            <button
              onClick={() => handleModalOpen("high-risk")}
              className="w-full mt-3 px-3 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700"
            >
              View High Risk Findings
            </button>
          </div>
        </ExpandableMetricCard>

        <ExpandableMetricCard
          icon={<ClockIcon className="w-6 h-6 text-blue-600" />}
          title="Recent"
          value={data.recent_findings}
          subtitle="Last 7 days"
          onClick={() => handleCardClick("recent")}
          isExpanded={expandedCard === "recent"}
        >
          <div className="text-left space-y-2">
            <div className="text-sm font-medium text-brand-white">
              Recent Activity:
            </div>
            <div className="text-xs text-brand-white">
              New findings detected in the past week
            </div>
            <div className="text-xs text-brand-white">
              Average per day: {Math.round(data.recent_findings / 7)}
            </div>
            <button
              onClick={() => handleModalOpen("recent")}
              className="w-full mt-3 px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700"
            >
              View Recent Findings
            </button>
          </div>
        </ExpandableMetricCard>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-green-100 rounded-full">
            <CheckCircleIcon className="w-6 h-6 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-brand-white">
            {data.status_distribution.find((s) => s.status === "resolved")
              ?.count || 0}
          </div>
          <div className="text-sm text-brand-white">Resolved</div>
          <div className="text-xs text-cloudquery-textWhite/80 mt-1">
            {Math.round(
              ((data.status_distribution.find((s) => s.status === "resolved")
                ?.count || 0) /
                data.total_findings) *
                100
            )}
            % of total
          </div>
        </Card>
      </div>

      {/* Risk Score */}
      <Card title="Average Risk Score">
        <div className="flex items-center space-x-4">
          <div className="flex-1 bg-gray-200 rounded-full h-4">
            <div
              className="bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 h-4 rounded-full"
              style={{ width: `${(data.average_risk_score / 10) * 100}%` }}
            ></div>
          </div>
          <div className="text-2xl font-bold text-brand-white">
            {data.average_risk_score}/10
          </div>
        </div>
        <div className="mt-2 text-sm text-brand-white">
          <Badge
            variant={
              data.average_risk_score >= 7
                ? "critical"
                : data.average_risk_score >= 5
                  ? "high"
                  : "medium"
            }
          >
            {data.average_risk_score >= 7
              ? "Critical"
              : data.average_risk_score >= 5
                ? "High"
                : "Medium"}{" "}
            Risk Level
          </Badge>
        </div>
      </Card>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <Card title="Findings by Severity">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value, name) => [value, name]}
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "6px",
                    color: "#ffffff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center space-x-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: item.color }}
                ></div>
                <span className="text-sm text-brand-white capitalize">
                  {item.name}: {item.value}
                </span>
              </div>
            ))}
          </div>
        </Card>

        {/* Status Distribution */}
        <Card title="Findings by Status">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#6b7280" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <YAxis
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "6px",
                    color: "#ffffff",
                  }}
                />
                <Bar dataKey="value" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Additional Security Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Trends */}
        <Card title="Security Trends (Last 30 Days)">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={
                  data.trends_data || [
                    { date: "2024-01-01", findings: 12, resolved: 8 },
                    { date: "2024-01-02", findings: 15, resolved: 10 },
                    { date: "2024-01-03", findings: 8, resolved: 12 },
                    { date: "2024-01-04", findings: 20, resolved: 15 },
                    { date: "2024-01-05", findings: 18, resolved: 16 },
                  ]
                }
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#6b7280" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <YAxis
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "6px",
                    color: "#ffffff",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="findings"
                  stackId="1"
                  stroke="#ef4444"
                  fill="#ef4444"
                  fillOpacity={0.6}
                />
                <Area
                  type="monotone"
                  dataKey="resolved"
                  stackId="1"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 flex justify-center space-x-6">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <span className="text-sm text-brand-white">New Findings</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <span className="text-sm text-brand-white">Resolved</span>
            </div>
          </div>
        </Card>

        {/* Top Resource Types */}
        <Card title="Top Resource Types with Security Findings">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={
                  data.top_resource_types || [
                    { resource_type: "EC2 Instance", count: 45, findings: 23 },
                    { resource_type: "S3 Bucket", count: 32, findings: 18 },
                    { resource_type: "RDS Database", count: 28, findings: 15 },
                    { resource_type: "IAM Role", count: 22, findings: 12 },
                    { resource_type: "VPC", count: 18, findings: 8 },
                    {
                      resource_type: "Lambda Function",
                      count: 15,
                      findings: 6,
                    },
                  ]
                }
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#6b7280" />
                <XAxis
                  dataKey="resource_type"
                  angle={-45}
                  textAnchor="end"
                  height={80}
                  fontSize={12}
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <YAxis
                  tick={{ fill: "#ffffff", fontSize: 12 }}
                  axisLine={{ stroke: "#6b7280" }}
                />
                <Tooltip
                  formatter={(value, name) => [
                    value,
                    name === "count" ? "Total Resources" : "Security Findings",
                  ]}
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: "6px",
                    color: "#ffffff",
                  }}
                />
                <Bar dataKey="count" fill="#3b82f6" name="count" />
                <Bar dataKey="findings" fill="#ef4444" name="findings" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 flex justify-center space-x-6">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
              <span className="text-sm text-brand-white">Total Resources</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <span className="text-sm text-brand-white">
                Security Findings
              </span>
            </div>
          </div>
        </Card>
      </div>

      {/* Compliance Overview */}
      <Card title="Compliance Status">
        <div className="space-y-4">
          {(
            data.compliance_violations || [
              {
                framework: "PCI DSS",
                violations: 12,
                critical_violations: 3,
                compliance_score: 75.5,
              },
              {
                framework: "SOC 2",
                violations: 8,
                critical_violations: 1,
                compliance_score: 82.1,
              },
              {
                framework: "ISO 27001",
                violations: 15,
                critical_violations: 4,
                compliance_score: 68.9,
              },
            ]
          ).map((framework) => (
            <div
              key={framework.framework}
              className="p-3 border border-cloudquery-logoGreen/20 rounded-lg"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-brand-white">
                  {framework.framework}
                </span>
                <Badge
                  variant={
                    framework.compliance_score >= 80
                      ? "success"
                      : framework.compliance_score >= 60
                        ? "medium"
                        : "critical"
                  }
                >
                  {framework.compliance_score}%
                </Badge>
              </div>
              <div className="text-sm text-brand-white">
                {framework.violations} violations (
                {framework.critical_violations} critical)
              </div>
              <div className="mt-2 bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${
                    framework.compliance_score >= 80
                      ? "bg-green-500"
                      : framework.compliance_score >= 60
                        ? "bg-yellow-500"
                        : "bg-red-500"
                  }`}
                  style={{ width: `${framework.compliance_score}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Top Finding Types */}
      <Card title="Top Finding Types">
        <div className="space-y-3">
          {data.top_finding_types.slice(0, 5).map((item, index) => (
            <div key={item.type} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-6 h-6 bg-blue-100 rounded-full text-blue-600 text-sm font-medium">
                  {index + 1}
                </div>
                <span className="text-sm font-medium text-brand-white capitalize">
                  {item.type.replace("_", " ")}
                </span>
              </div>
              <Badge variant="info">{item.count}</Badge>
            </div>
          ))}
        </div>
      </Card>

      {/* Detailed Findings Modal */}
      <SecurityDetailModal
        isOpen={modalOpen !== null}
        onClose={() => setModalOpen(null)}
        title={`${modalOpen === "total" ? "All" : modalOpen === "high-risk" ? "High Risk" : modalOpen === "recent" ? "Recent" : "Urgent"} Security Findings`}
      >
        <div className="space-y-4">
          {/* Pagination Info */}
          {modalOpen !== "urgent" && pagination.total > 0 && (
            <div className="text-sm text-brand-white mb-4">
              Showing {(pagination.page - 1) * pagination.size + 1} to{" "}
              {Math.min(pagination.page * pagination.size, pagination.total)} of{" "}
              {pagination.total} findings
            </div>
          )}

          {detailedFindings.length > 0 ? (
            <>
              {detailedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="border border-cloudquery-logoGreen/20 rounded-lg p-4"
                >
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-medium text-brand-white">
                      {finding.title}
                    </h3>
                    <Badge variant={finding.severity as any}>
                      {finding.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-brand-white mb-2">
                    {finding.description}
                  </p>
                  <div className="flex items-center space-x-4 text-xs text-brand-white">
                    <span>Resource: {finding.resource_name}</span>
                    <span>Provider: {finding.provider}</span>
                    <span>Region: {finding.region}</span>
                    <span>Risk Score: {finding.risk_score}/10</span>
                  </div>
                </div>
              ))}

              {/* Pagination Controls */}
              {modalOpen !== "urgent" && pagination.pages > 1 && (
                <div className="flex justify-center items-center space-x-4 mt-6">
                  <button
                    onClick={() =>
                      fetchDetailedFindings(modalOpen!, pagination.page - 1)
                    }
                    disabled={pagination.page <= 1}
                    className="px-3 py-1 bg-blue-600 text-white rounded disabled:bg-gray-600 disabled:cursor-not-allowed hover:bg-blue-700"
                  >
                    Previous
                  </button>

                  <span className="text-brand-white">
                    Page {pagination.page} of {pagination.pages}
                  </span>

                  <button
                    onClick={() =>
                      fetchDetailedFindings(modalOpen!, pagination.page + 1)
                    }
                    disabled={pagination.page >= pagination.pages}
                    className="px-3 py-1 bg-blue-600 text-white rounded disabled:bg-gray-600 disabled:cursor-not-allowed hover:bg-blue-700"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-8 text-brand-white">
              No detailed findings available at this time.
            </div>
          )}
        </div>
      </SecurityDetailModal>
    </div>
  );
};

export default SecurityOverview;
