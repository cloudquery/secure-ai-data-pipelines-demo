/**
 * CloudQuery Footer Component
 */
import React from "react";
import { CloudQueryLogo } from "./CloudQueryLogo";
import {
  DocumentTextIcon,
  HomeIcon,
  CodeBracketIcon,
  BookOpenIcon,
  ArrowTopRightOnSquareIcon,
} from "@heroicons/react/24/outline";

export const Footer: React.FC = () => {
  const currentYear = new Date().getFullYear();

  const footerLinks = {
    product: [
      {
        name: "Documentation",
        href: "https://docs.cloudquery.io",
        icon: BookOpenIcon,
      },
      { name: "Homepage", href: "https://www.cloudquery.io", icon: HomeIcon },
      {
        name: "GitHub",
        href: "https://github.com/cloudquery/cloudquery",
        icon: CodeBracketIcon,
      },
    ],
    resources: [
      {
        name: "Getting Started",
        href: "https://docs.cloudquery.io/docs/getting-started",
      },
      { name: "Plugins", href: "https://docs.cloudquery.io/docs/plugins" },
      {
        name: "Community",
        href: "https://github.com/cloudquery/cloudquery/discussions",
      },
    ],
    support: [
      { name: "Discord", href: "https://cloudquery.io/discord" },
      { name: "Twitter", href: "https://twitter.com/cloudqueryio" },
      { name: "Blog", href: "https://www.cloudquery.io/blog" },
    ],
  };

  return (
    <footer className="bg-cloudquery-darkGray text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Brand Section */}
          <div className="lg:col-span-1">
            <CloudQueryLogo size="lg" className="mb-4" />
            <p className="text-gray-300 text-sm leading-relaxed mb-4">
              CloudQuery is an open-source cloud asset inventory powered by SQL.
              Query your cloud infrastructure with SQL for security, compliance,
              and cost optimization.
            </p>
            <div className="flex space-x-4">
              <a
                href="https://github.com/cloudquery/cloudquery"
                className="text-gray-400 hover:text-white transition-colors"
                target="_blank"
                rel="noopener noreferrer"
              >
                <span className="sr-only">GitHub</span>
                <svg
                  className="h-5 w-5"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                </svg>
              </a>
              <a
                href="https://twitter.com/cloudqueryio"
                className="text-gray-400 hover:text-white transition-colors"
                target="_blank"
                rel="noopener noreferrer"
              >
                <span className="sr-only">Twitter</span>
                <svg
                  className="h-5 w-5"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z" />
                </svg>
              </a>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">
              Product
            </h3>
            <ul className="space-y-3">
              {footerLinks.product.map((link) => (
                <li key={link.name}>
                  <a
                    href={link.href}
                    className="flex items-center text-sm text-gray-300 hover:text-white transition-colors group"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <link.icon className="h-4 w-4 mr-2" />
                    {link.name}
                    <ArrowTopRightOnSquareIcon className="h-3 w-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources Links */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">
              Resources
            </h3>
            <ul className="space-y-3">
              {footerLinks.resources.map((link) => (
                <li key={link.name}>
                  <a
                    href={link.href}
                    className="text-sm text-gray-300 hover:text-white transition-colors"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Support Links */}
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">
              Support
            </h3>
            <ul className="space-y-3">
              {footerLinks.support.map((link) => (
                <li key={link.name}>
                  <a
                    href={link.href}
                    className="text-sm text-gray-300 hover:text-white transition-colors"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="mt-8 pt-8 border-t border-gray-700">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-sm text-gray-400">
              © {currentYear} CloudQuery. All rights reserved.
            </p>
            <div className="mt-4 md:mt-0">
              <p className="text-sm text-gray-400">
                Built with{" "}
                <a
                  href="https://www.cloudquery.io"
                  className="text-cloudquery-blue hover:text-cloudquery-lightBlue transition-colors"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  CloudQuery
                </a>{" "}
                for secure AI data pipelines
              </p>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;


