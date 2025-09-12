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
import About from "../components/dashboard/About";
import apiClient from "../lib/api/client";
import {
  CloudIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CpuChipIcon,
  ArrowPathIcon,
  SparklesIcon,
  InformationCircleIcon,
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
    "overview" | "security" | "ai-analysis" | "about"
  >("overview");
  const [resourceOverview, setResourceOverview] =
    useState<ResourceOverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  useEffect(() => {
    // Initialize lastRefresh on client side to avoid hydration mismatch
    setLastRefresh(new Date());
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      console.log("Fetching resource overview data...");
      const [resourceData] = await Promise.all([
        apiClient.getResourceOverview(),
        // Add more data fetching as needed
      ]);

      console.log("Resource data received:", resourceData);
      setResourceOverview(resourceData);

      setLastRefresh(new Date());
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
      // Set some mock data for development
      setResourceOverview({
        total_resources: 0,
        public_resources: 0,
        unencrypted_resources: 0,
        providers: [],
        resource_types: [],
        security_findings: [],
      });
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
    { id: "about", label: "About", icon: InformationCircleIcon },
  ];

  return (
    <div className="min-h-screen bg-cloudquery-bgDarkTeal">
      <Head>
        <title>CloudQuery Secure AI Data Pipeline - Dashboard</title>
        <meta
          name="description"
          content="CloudQuery-powered cloud security analysis and monitoring dashboard for secure AI data pipelines"
        />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      {/* Header */}
      <header className="bg-cloudquery-bgGradient shadow-sm border-b border-cloudquery-logoGreen/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-4">
              <CloudQueryLogo size="lg" />
              <div>
                <h1 className="text-3xl font-bold text-brand-white">
                  Secure AI Data Pipeline
                </h1>
                <p className="text-cloudquery-textWhite/80 mt-1">
                  CloudQuery-powered cloud security analysis and monitoring
                  dashboard
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-cloudquery-textWhite/70">
                Last updated:{" "}
                {lastRefresh ? lastRefresh.toLocaleTimeString() : "Loading..."}
              </div>
              <button
                onClick={handleRefresh}
                disabled={loading}
                className="flex items-center space-x-2 px-4 py-2 bg-cloudquery-logoGreen text-cloudquery-textWhite rounded-md hover:bg-cloudquery-ctaGreen disabled:opacity-50 transition-colors"
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
      <nav className="bg-cloudquery-bgGradient shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? "border-cloudquery-logoGreen text-cloudquery-logoGreen"
                    : "border-transparent text-cloudquery-textWhite/70 hover:text-cloudquery-textWhite hover:border-cloudquery-logoGreen/50"
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
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-cloudquery-logoGreen/20 rounded-full">
                    <CloudIcon className="w-6 h-6 text-cloudquery-logoGreen" />
                  </div>
                  <div className="text-2xl font-bold text-brand-white">
                    {resourceOverview.total_resources}
                  </div>
                  <div className="text-sm text-cloudquery-textWhite/80">
                    Total Resources
                  </div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-red-500/20 rounded-full">
                    <ExclamationTriangleIcon className="w-6 h-6 text-red-400" />
                  </div>
                  <div className="text-2xl font-bold text-brand-white">
                    {resourceOverview.public_resources}
                  </div>
                  <div className="text-sm text-cloudquery-textWhite/80">
                    Public Resources
                  </div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-orange-500/20 rounded-full">
                    <ShieldCheckIcon className="w-6 h-6 text-orange-400" />
                  </div>
                  <div className="text-2xl font-bold text-brand-white">
                    {resourceOverview.unencrypted_resources}
                  </div>
                  <div className="text-sm text-cloudquery-textWhite/80">
                    Unencrypted
                  </div>
                </Card>

                <Card className="text-center">
                  <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-green-500/20 rounded-full">
                    <CpuChipIcon className="w-6 h-6 text-green-400" />
                  </div>
                  <div className="text-2xl font-bold text-brand-white">
                    {resourceOverview.providers.length}
                  </div>
                  <div className="text-sm text-cloudquery-textWhite/80">
                    Cloud Providers
                  </div>
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
                      className="text-center p-4 bg-cloudquery-bgDarkTeal/50 rounded-lg border border-cloudquery-logoGreen/20"
                    >
                      <div className="text-2xl font-bold text-brand-white mb-2">
                        {provider.count}
                      </div>
                      <div className="text-sm font-medium text-brand-white mb-1">
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
                          <div className="flex items-center justify-center w-6 h-6 bg-cloudquery-logoGreen/20 rounded-full text-cloudquery-logoGreen text-sm font-medium">
                            {index + 1}
                          </div>
                          <span className="text-sm font-medium text-brand-white">
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

        {activeTab === "about" && <About />}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}
