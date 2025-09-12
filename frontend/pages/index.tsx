/**
 * Main Dashboard Page
 */
import React, { useState, useEffect } from "react";
import Head from "next/head";
import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { CloudQueryLogo } from "../components/ui/CloudQueryLogo";
import { Footer } from "../components/ui/Footer";
import SecurityOverview from "../components/dashboard/SecurityOverview";
import { AIAnalysis } from "../components/dashboard/AIAnalysis";
import apiClient from "../lib/api/client";
import {
  CloudIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CpuChipIcon,
  ArrowPathIcon,
  SparklesIcon,
} from "@heroicons/react/24/outline";

interface ResourceOverviewData {
  total_resources: number;
  public_resources: number;
  unencrypted_resources: number;
  providers: Array<{
    name: string;
    display_name: string;
    count: number;
  }>;
  resource_types: Array<{
    type: string;
    count: number;
  }>;
  security_findings: Array<{
    severity: string;
    count: number;
  }>;
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<
    "overview" | "security" | "ai-analysis"
  >("overview");
  const [resourceOverview, setResourceOverview] =
    useState<ResourceOverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [resourceData] = await Promise.all([
        apiClient.getResourceOverview(),
        // Add more data fetching as needed
      ]);

      setResourceOverview(resourceData);

      setLastRefresh(new Date());
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    fetchData();
  };

  const tabs = [
    { id: "overview", label: "Overview", icon: CpuChipIcon },
    { id: "security", label: "Security", icon: ShieldCheckIcon },
    { id: "ai-analysis", label: "AI Analysis", icon: SparklesIcon },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <Head>
        <title>CloudQuery Secure AI Data Pipeline - Dashboard</title>
        <meta
          name="description"
          content="CloudQuery-powered cloud security analysis and monitoring dashboard for secure AI data pipelines"
        />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-4">
              <CloudQueryLogo size="lg" />
              <div>
                <h1 className="text-3xl font-bold text-cloudquery-darkBlue">
                  Secure AI Data Pipeline
                </h1>
                <p className="text-cloudquery-gray mt-1">
                  CloudQuery-powered cloud security analysis and monitoring
                  dashboard
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-500">
                Last updated: {lastRefresh.toLocaleTimeString()}
              </div>
              <button
                onClick={handleRefresh}
                disabled={loading}
                className="flex items-center space-x-2 px-4 py-2 bg-cloudquery-blue text-white rounded-md hover:bg-cloudquery-darkBlue disabled:opacity-50 transition-colors"
              >
                <ArrowPathIcon
                  className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
                />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? "border-cloudquery-blue text-cloudquery-blue"
                    : "border-transparent text-gray-500 hover:text-cloudquery-gray hover:border-gray-300"
                }`}
              >
                <tab.icon className="w-5 h-5" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === "overview" && (
          <div className="space-y-8">
            {/* Resource Overview Cards */}
            {resourceOverview && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-cloudquery-50 rounded-full">
                    <CloudIcon className="w-6 h-6 text-cloudquery-blue" />
                  </div>
                  <div className="text-2xl font-bold text-gray-900">
                    {resourceOverview.total_resources}
                  </div>
                  <div className="text-sm text-gray-600">Total Resources</div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-red-100 rounded-full">
                    <ExclamationTriangleIcon className="w-6 h-6 text-red-600" />
                  </div>
                  <div className="text-2xl font-bold text-gray-900">
                    {resourceOverview.public_resources}
                  </div>
                  <div className="text-sm text-gray-600">Public Resources</div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-orange-100 rounded-full">
                    <ShieldCheckIcon className="w-6 h-6 text-orange-600" />
                  </div>
                  <div className="text-2xl font-bold text-gray-900">
                    {resourceOverview.unencrypted_resources}
                  </div>
                  <div className="text-sm text-gray-600">Unencrypted</div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-green-100 rounded-full">
                    <CpuChipIcon className="w-6 h-6 text-green-600" />
                  </div>
                  <div className="text-2xl font-bold text-gray-900">
                    {resourceOverview.providers.length}
                  </div>
                  <div className="text-sm text-gray-600">Cloud Providers</div>
                </Card>
              </div>
            )}

            {/* Provider Distribution */}
            {resourceOverview && (
              <Card title="Cloud Providers">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {resourceOverview.providers.map((provider) => (
                    <div
                      key={provider.name}
                      className="text-center p-4 bg-gray-50 rounded-lg"
                    >
                      <div className="text-2xl font-bold text-gray-900 mb-2">
                        {provider.count}
                      </div>
                      <div className="text-sm font-medium text-gray-900 mb-1">
                        {provider.display_name}
                      </div>
                      <Badge variant="info" size="sm">
                        {provider.name.toUpperCase()}
                      </Badge>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* Top Resource Types */}
            {resourceOverview && (
              <Card title="Top Resource Types">
                <div className="space-y-3">
                  {resourceOverview.resource_types
                    .slice(0, 8)
                    .map((type, index) => (
                      <div
                        key={type.type}
                        className="flex items-center justify-between"
                      >
                        <div className="flex items-center space-x-3">
                          <div className="flex items-center justify-center w-6 h-6 bg-cloudquery-100 rounded-full text-cloudquery-blue text-sm font-medium">
                            {index + 1}
                          </div>
                          <span className="text-sm font-medium text-gray-900">
                            {type.type.replace("_", " ")}
                          </span>
                        </div>
                        <Badge variant="default">{type.count}</Badge>
                      </div>
                    ))}
                </div>
              </Card>
            )}
          </div>
        )}

        {activeTab === "security" && <SecurityOverview />}

        {activeTab === "ai-analysis" && <AIAnalysis />}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}
