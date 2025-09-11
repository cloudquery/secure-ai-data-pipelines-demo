/**
 * Security Overview Dashboard Component
 */
import React, { useState, useEffect } from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { 
  ShieldExclamationIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon 
} from '@heroicons/react/24/outline';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import apiClient from '../../lib/api/client';

interface SecurityDashboardData {
  total_findings: number;
  high_risk_findings: number;
  auto_remediable_findings: number;
  recent_findings: number;
  average_risk_score: number;
  severity_distribution: Array<{ severity: string; count: number }>;
  status_distribution: Array<{ status: string; count: number }>;
  top_finding_types: Array<{ type: string; count: number }>;
}

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#0284c7',
};

const STATUS_COLORS = {
  open: '#dc2626',
  in_progress: '#d97706',
  resolved: '#16a34a',
  false_positive: '#6b7280',
};

export const SecurityOverview: React.FC = () => {
  const [data, setData] = useState<SecurityDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await apiClient.getSecurityDashboard();
      setData(response);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
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
        <h3 className="text-lg font-medium text-gray-900 mb-2">Error Loading Dashboard</h3>
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

  const severityData = data.severity_distribution.map(item => ({
    name: item.severity,
    value: item.count,
    color: SEVERITY_COLORS[item.severity as keyof typeof SEVERITY_COLORS] || '#6b7280'
  }));

  const statusData = data.status_distribution.map(item => ({
    name: item.status,
    value: item.count,
    color: STATUS_COLORS[item.status as keyof typeof STATUS_COLORS] || '#6b7280'
  }));

  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-red-100 rounded-full">
            <ShieldExclamationIcon className="w-6 h-6 text-red-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{data.total_findings}</div>
          <div className="text-sm text-gray-600">Total Findings</div>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-orange-100 rounded-full">
            <ExclamationTriangleIcon className="w-6 h-6 text-orange-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{data.high_risk_findings}</div>
          <div className="text-sm text-gray-600">High Risk</div>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-green-100 rounded-full">
            <CheckCircleIcon className="w-6 h-6 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{data.auto_remediable_findings}</div>
          <div className="text-sm text-gray-600">Auto-Remediable</div>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-blue-100 rounded-full">
            <ClockIcon className="w-6 h-6 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{data.recent_findings}</div>
          <div className="text-sm text-gray-600">Recent (7 days)</div>
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
          <div className="text-2xl font-bold text-gray-900">
            {data.average_risk_score}/10
          </div>
        </div>
        <div className="mt-2 text-sm text-gray-600">
          <Badge variant={data.average_risk_score >= 7 ? 'critical' : data.average_risk_score >= 5 ? 'high' : 'medium'}>
            {data.average_risk_score >= 7 ? 'Critical' : data.average_risk_score >= 5 ? 'High' : 'Medium'} Risk Level
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
                <Tooltip formatter={(value, name) => [value, name]} />
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
                <span className="text-sm text-gray-600 capitalize">
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
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Top Finding Types */}
      <Card title="Top Finding Types">
        <div className="space-y-3">
          {data.top_finding_types.slice(0, 5).map((item, index) => (
            <div key={item.type} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-6 h-6 bg-blue-100 rounded-full text-blue-600 text-sm font-medium">
                  {index + 1}
                </div>
                <span className="text-sm font-medium text-gray-900 capitalize">
                  {item.type.replace('_', ' ')}
                </span>
              </div>
              <Badge variant="info">{item.count}</Badge>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default SecurityOverview;
