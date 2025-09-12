/**
 * About Page Component
 * Shows AI data pipeline visualization and security considerations
 */
import React, { useState, useEffect } from "react";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import {
  CloudIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  CircleStackIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  InformationCircleIcon,
  ChartBarIcon,
} from "@heroicons/react/24/outline";

interface PipelineStep {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<any>;
  color: string;
  position: { x: number; y: number };
}

const About: React.FC = () => {
  const [activeStep, setActiveStep] = useState<string | null>(null);
  const [animationPhase, setAnimationPhase] = useState(0);

  const pipelineSteps: PipelineStep[] = [
    {
      id: "cloud-resources",
      title: "Cloud Resources",
      description: "AWS, Azure, GCP infrastructure and services",
      icon: CloudIcon,
      color: "bg-blue-500",
      position: { x: 50, y: 100 },
    },
    {
      id: "cloudquery",
      title: "CloudQuery",
      description: "Extract, transform, and normalize cloud data",
      icon: CircleStackIcon,
      color: "bg-green-500",
      position: { x: 200, y: 100 },
    },
    {
      id: "data-sanitization",
      title: "Data Sanitization",
      description: "Remove sensitive data and PII",
      icon: ShieldCheckIcon,
      color: "bg-purple-500",
      position: { x: 350, y: 100 },
    },
    {
      id: "ai-analysis",
      title: "AI Analysis",
      description: "Machine learning security insights",
      icon: CpuChipIcon,
      color: "bg-orange-500",
      position: { x: 500, y: 100 },
    },
    {
      id: "dashboard",
      title: "Security Dashboard",
      description: "Visualize findings and recommendations",
      icon: ChartBarIcon,
      color: "bg-indigo-500",
      position: { x: 650, y: 100 },
    },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setAnimationPhase((prev) => (prev + 1) % pipelineSteps.length);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-8">
      {/* Pipeline Visualization */}
      <Card title="AI Data Pipeline Architecture" className="overflow-hidden">
        <div className="text-center">
          <h3 className="text-lg font-semibold text-brand-white mb-2">
            How Our AI Data Pipeline Works
          </h3>
          <p className="text-cloudquery-textWhite/80 max-w-4xl mx-auto">
            Our secure AI data pipeline leverages CloudQuery as the foundational
            data extraction and normalization layer, ensuring that cloud
            infrastructure data is properly collected, sanitized, and prepared
            for AI analysis while maintaining the highest security standards.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mt-6">
          {pipelineSteps.map((step, index) => {
            const IconComponent = step.icon;
            return (
              <div
                key={step.id}
                className="text-center p-4 bg-cloudquery-bgDarkTeal/30 rounded-lg border border-cloudquery-logoGreen/20 hover:border-cloudquery-logoGreen/40 transition-colors"
              >
                <div
                  className={`w-12 h-12 mx-auto mb-3 rounded-full ${step.color} flex items-center justify-center`}
                >
                  <IconComponent className="w-6 h-6 text-white" />
                </div>
                <h4 className="font-medium text-brand-white text-sm mb-1">
                  {step.title}
                </h4>
                <p className="text-xs text-cloudquery-textWhite/70">
                  {step.description}
                </p>
                {step.id === "cloudquery" && (
                  <div className="mt-2">
                    <Badge variant="success" size="sm">
                      Key Component
                    </Badge>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Security Considerations */}
      <Card title="Security Considerations for AI Data Pipelines">
        <div className="text-center mb-8">
          <h3 className="text-lg font-semibold text-brand-white mb-2">
            Building Secure AI Data Pipelines
          </h3>
          <p className="text-cloudquery-textWhite/80 max-w-4xl mx-auto">
            When building AI data pipelines for cloud providers, security must
            be considered at every stage. Below are key security considerations,
            best practices, and important caveats to keep in mind.
          </p>
        </div>

        <div className="space-y-6">
          {/* Data Privacy */}
          <div className="bg-cloudquery-bgDarkTeal/30 rounded-lg border border-cloudquery-logoGreen/20 p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <span className="text-red-400">⚠️</span>
                <div>
                  <h4 className="text-lg font-semibold text-brand-white">
                    Sensitive Data Handling
                  </h4>
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                    HIGH PRIORITY
                  </span>
                </div>
              </div>
            </div>

            <p className="text-cloudquery-textWhite/80 mb-6">
              Protecting personally identifiable information (PII) and sensitive
              business data throughout the pipeline
            </p>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h5 className="font-semibold text-brand-white mb-3 flex items-center">
                  <span className="text-green-400 mr-2">✅</span>
                  Best Practices
                </h5>
                <ul className="space-y-2">
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-green-400 rounded-full mt-2 mr-3 flex-shrink-0" />
                    <span className="text-sm text-cloudquery-textWhite/80">
                      Implement data classification and tagging
                    </span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-green-400 rounded-full mt-2 mr-3 flex-shrink-0" />
                    <span className="text-sm text-cloudquery-textWhite/80">
                      Use encryption at rest and in transit
                    </span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-green-400 rounded-full mt-2 mr-3 flex-shrink-0" />
                    <span className="text-sm text-cloudquery-textWhite/80">
                      Apply data masking and anonymization techniques
                    </span>
                  </li>
                </ul>
              </div>

              <div>
                <h5 className="font-semibold text-brand-white mb-3 flex items-center">
                  <span className="text-yellow-400 mr-2">⚠️</span>
                  Important Caveats
                </h5>
                <ul className="space-y-2">
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-yellow-400 rounded-full mt-2 mr-3 flex-shrink-0" />
                    <span className="text-sm text-cloudquery-textWhite/80">
                      AI models may inadvertently memorize sensitive data
                    </span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-yellow-400 rounded-full mt-2 mr-3 flex-shrink-0" />
                    <span className="text-sm text-cloudquery-textWhite/80">
                      Data lineage tracking becomes critical for compliance
                    </span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Additional Resources */}
          <div className="mt-8 p-6 bg-gradient-to-r from-cloudquery-logoGreen/10 to-blue-500/10 rounded-lg border border-cloudquery-logoGreen/30">
            <h4 className="text-lg font-semibold text-brand-white mb-3 flex items-center">
              <span className="text-cloudquery-logoGreen mr-2">ℹ️</span>
              Additional Resources
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-brand-white mb-2">
                  Security Frameworks
                </h5>
                <ul className="text-sm text-cloudquery-textWhite/80 space-y-1">
                  <li>• NIST Cybersecurity Framework</li>
                  <li>• CIS Controls for Cloud Security</li>
                  <li>• OWASP AI Security Guidelines</li>
                  <li>• Cloud Security Alliance (CSA) CCM</li>
                </ul>
              </div>
              <div>
                <h5 className="font-medium text-brand-white mb-2">
                  Compliance Standards
                </h5>
                <ul className="text-sm text-cloudquery-textWhite/80 space-y-1">
                  <li>• SOC 2 Type II</li>
                  <li>• ISO 27001</li>
                  <li>• GDPR (EU)</li>
                  <li>• HIPAA (Healthcare)</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default About;
