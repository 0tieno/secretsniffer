import React, { useState } from "react";
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  Github,
  Clock,
  FileText,
  GitCommit,
} from "lucide-react";
import clsx from "clsx";

const SecretSniffer = () => {
  const [repoUrl, setRepoUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState("");

  // Mock scan function for frontend demo
  const mockScan = async (url) => {
    await new Promise((resolve) => setTimeout(resolve, 3000)); // Simulate scan time

    // Mock results - replace with real API call later
    const mockResults = {
      repoName: url.split("/").pop(),
      totalSecrets: Math.floor(Math.random() * 10),
      scanDate: new Date().toISOString(),
      findings: [
        {
          id: 1,
          file: "config/database.js",
          commit: "a1b2c3d",
          secretType: "Database Password",
          severity: "high",
          lineNumber: 15,
          snippet: 'password: "super_secret_password"',
        },
        {
          id: 2,
          file: ".env.example",
          commit: "e4f5g6h",
          secretType: "API Key",
          severity: "medium",
          lineNumber: 7,
          snippet: "API_KEY=sk-1234567890abcdef",
        },
      ],
    };

    return mockResults;
  };

  const handleScan = async () => {
    if (!repoUrl.trim()) {
      setError("Please enter a GitHub repository URL");
      return;
    }

    if (!repoUrl.includes("github.com")) {
      setError("Please enter a valid GitHub URL");
      return;
    }

    setError("");
    setIsScanning(true);
    setScanResults(null);

    try {
      const results = await mockScan(repoUrl);
      setScanResults(results);
    } catch (err) {
      setError("Failed to scan repository. Please try again.");
    } finally {
      setIsScanning(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "high":
        return "text-red-600 bg-red-50 border-red-200";
      case "medium":
        return "text-yellow-600 bg-yellow-50 border-yellow-200";
      case "low":
        return "text-blue-600 bg-blue-50 border-blue-200";
      default:
        return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-indigo-600 mr-3" />
            <h1 className="text-4xl font-bold text-gray-900">GFaaS</h1>
          </div>
          <p className="text-xl text-gray-600 mb-2">
            Git Forensics as a Service
          </p>
          <p className="text-gray-500 max-w-2xl mx-auto">
            Scan your GitHub repositories for leaked secrets and sensitive
            information. Get detailed reports with commit history and
            remediation suggestions.
          </p>
        </div>

        {/* Scan Interface */}
        <div className="max-w-4xl mx-auto">
          <div className="bg-white rounded-xl shadow-lg p-8 mb-8">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">
              Scan Repository
            </h2>

            <div className="flex flex-col sm:flex-row gap-4 mb-4">
              <div className="flex-1">
                <label
                  htmlFor="repo-url"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  GitHub Repository URL
                </label>
                <div className="relative">
                  <Github className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                  <input
                    id="repo-url"
                    type="url"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/username/repository"
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <button
                onClick={handleScan}
                disabled={isScanning}
                className={clsx(
                  "px-8 py-3 rounded-lg font-medium flex items-center justify-center transition-all",
                  isScanning
                    ? "bg-gray-400 cursor-not-allowed"
                    : "bg-indigo-600 hover:bg-indigo-700 transform hover:scale-105"
                )}
              >
                {isScanning ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="h-5 w-5 mr-2" />
                    Scan Now
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center">
                <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                <span className="text-red-700">{error}</span>
              </div>
            )}
          </div>

          {/* Scan Results */}
          {scanResults && (
            <div className="bg-white rounded-xl shadow-lg p-8">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-semibold text-gray-900">
                    Scan Results
                  </h3>
                  <p className="text-gray-600">
                    Repository: {scanResults.repoName}
                  </p>
                </div>
                <div className="text-right">
                  <div className="flex items-center text-gray-500 mb-1">
                    <Clock className="h-4 w-4 mr-1" />
                    {new Date(scanResults.scanDate).toLocaleString()}
                  </div>
                </div>
              </div>

              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="bg-gradient-to-r from-red-500 to-red-600 rounded-lg p-6 text-white">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-red-100">Total Secrets</p>
                      <p className="text-3xl font-bold">
                        {scanResults.totalSecrets}
                      </p>
                    </div>
                    <AlertTriangle className="h-10 w-10 text-red-200" />
                  </div>
                </div>

                <div className="bg-gradient-to-r from-blue-500 to-blue-600 rounded-lg p-6 text-white">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100">Files Affected</p>
                      <p className="text-3xl font-bold">
                        {scanResults.findings.length}
                      </p>
                    </div>
                    <FileText className="h-10 w-10 text-blue-200" />
                  </div>
                </div>

                <div className="bg-gradient-to-r from-green-500 to-green-600 rounded-lg p-6 text-white">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100">Status</p>
                      <p className="text-lg font-semibold">
                        {scanResults.totalSecrets === 0
                          ? "Clean"
                          : "Needs Review"}
                      </p>
                    </div>
                    {scanResults.totalSecrets === 0 ? (
                      <CheckCircle className="h-10 w-10 text-green-200" />
                    ) : (
                      <AlertTriangle className="h-10 w-10 text-green-200" />
                    )}
                  </div>
                </div>
              </div>

              {/* Findings Table */}
              {scanResults.findings.length > 0 ? (
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-4">
                    Secret Findings
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse">
                      <thead>
                        <tr className="bg-gray-50">
                          <th className="text-left p-4 border-b border-gray-200 font-medium text-gray-700">
                            File
                          </th>
                          <th className="text-left p-4 border-b border-gray-200 font-medium text-gray-700">
                            Secret Type
                          </th>
                          <th className="text-left p-4 border-b border-gray-200 font-medium text-gray-700">
                            Severity
                          </th>
                          <th className="text-left p-4 border-b border-gray-200 font-medium text-gray-700">
                            Commit
                          </th>
                          <th className="text-left p-4 border-b border-gray-200 font-medium text-gray-700">
                            Line
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResults.findings.map((finding) => (
                          <tr key={finding.id} className="hover:bg-gray-50">
                            <td className="p-4 border-b border-gray-100">
                              <div className="flex items-center">
                                <FileText className="h-4 w-4 text-gray-400 mr-2" />
                                <span className="font-mono text-sm">
                                  {finding.file}
                                </span>
                              </div>
                            </td>
                            <td className="p-4 border-b border-gray-100">
                              <span className="font-medium">
                                {finding.secretType}
                              </span>
                            </td>
                            <td className="p-4 border-b border-gray-100">
                              <span
                                className={clsx(
                                  "px-3 py-1 rounded-full text-xs font-medium border",
                                  getSeverityColor(finding.severity)
                                )}
                              >
                                {finding.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="p-4 border-b border-gray-100">
                              <div className="flex items-center">
                                <GitCommit className="h-4 w-4 text-gray-400 mr-2" />
                                <span className="font-mono text-sm">
                                  {finding.commit}
                                </span>
                              </div>
                            </td>
                            <td className="p-4 border-b border-gray-100">
                              <span className="text-gray-600">
                                #{finding.lineNumber}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Remediation Suggestions */}
                  <div className="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-6">
                    <h5 className="text-lg font-semibold text-blue-900 mb-3">
                      🔧 Remediation Suggestions
                    </h5>
                    <ul className="space-y-2 text-blue-800">
                      <li>
                        • Add sensitive files to `.gitignore` to prevent future
                        commits
                      </li>
                      <li>
                        • Rotate any exposed API keys, passwords, or tokens
                        immediately
                      </li>
                      <li>• Use environment variables for configuration</li>
                      <li>
                        • Consider using a secrets management service like Azure
                        Key Vault
                      </li>
                      <li>
                        • Run pre-commit hooks to catch secrets before they're
                        committed
                      </li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                  <h4 className="text-xl font-semibold text-gray-900 mb-2">
                    🎉 No Secrets Found!
                  </h4>
                  <p className="text-gray-600">
                    Your repository appears to be clean of leaked secrets.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="text-center mt-16 text-gray-500">
          <p>Built with ❤️ for secure development practices</p>
        </div>
      </div>
    </div>
  );
};

export default SecretSniffer;
