'use client';

import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface ScanResultsProps {
  results: any;
}

export default function ScanResults({ results }: ScanResultsProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'subdomains' | 'vulnerabilities' | 'endpoints'>('overview');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    return `${(seconds / 60).toFixed(1)}m`;
  };

  const getRiskColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-900 text-red-100';
      case 'HIGH':
        return 'bg-orange-900 text-orange-100';
      case 'MEDIUM':
        return 'bg-yellow-900 text-yellow-100';
      case 'LOW':
        return 'bg-blue-900 text-blue-100';
      default:
        return 'bg-slate-700 text-slate-100';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">📊 Scan Results</h2>
        <p className="text-slate-400">Target: <code className="text-blue-300">{results.target}</code></p>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-700 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-400">
            {results.subdomains?.length || 0}
          </div>
          <div className="text-sm text-slate-400">Subdomains</div>
        </div>
        <div className="bg-slate-700 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-400">
            {results.alive_subdomains?.length || 0}
          </div>
          <div className="text-sm text-slate-400">Alive Subdomains</div>
        </div>
        <div className="bg-slate-700 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {Object.keys(results.endpoints || {}).length}
          </div>
          <div className="text-sm text-slate-400">Endpoints</div>
        </div>
        <div className="bg-slate-700 rounded-lg p-4">
          <div className="text-2xl font-bold text-red-400">
            {results.vulnerabilities?.length || 0}
          </div>
          <div className="text-sm text-slate-400">Vulnerabilities</div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-slate-700">
        {['overview', 'subdomains', 'vulnerabilities', 'endpoints'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === tab
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-slate-700 rounded-lg p-4">
            <h3 className="font-bold text-white mb-2">📈 Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
              <div>
                <span className="text-slate-400">Scan Time:</span>
                <p className="text-white font-medium">{formatTime(results.elapsed_time || 0)}</p>
              </div>
              <div>
                <span className="text-slate-400">URLs Crawled:</span>
                <p className="text-white font-medium">{results.urls?.length || 0}</p>
              </div>
              <div>
                <span className="text-slate-400">High Risk Endpoints:</span>
                <p className="text-white font-medium">
                  {results.scored_endpoints?.filter((e: any) => e.risk_level === 'HIGH' || e.risk_level === 'CRITICAL').length || 0}
                </p>
              </div>
            </div>
          </div>

          {results.wordlists_used && (
            <div className="bg-slate-700 rounded-lg p-4">
              <h3 className="font-bold text-white mb-2">🔤 Wordlists Used</h3>
              <div className="space-y-2 text-sm">
                <div>
                  <span className="text-slate-400">Subdomain:</span>
                  <p className="text-white">{results.wordlists_used.subdomain || 'default'}</p>
                </div>
                <div>
                  <span className="text-slate-400">Directory:</span>
                  <p className="text-white">{results.wordlists_used.directory || 'default'}</p>
                </div>
              </div>
            </div>
          )}

          {results.attack_paths?.length > 0 && (
            <div className="bg-slate-700 rounded-lg p-4">
              <h3 className="font-bold text-white mb-2">🛣️ Attack Paths ({results.attack_paths.length})</h3>
              <p className="text-slate-400 text-sm">
                {results.attack_paths.slice(0, 2).map((path: any, i: number) => (
                  <div key={i} className="mb-2">
                    {typeof path === 'string' ? path : JSON.stringify(path)}
                  </div>
                ))}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Subdomains Tab */}
      {activeTab === 'subdomains' && (
        <div className="space-y-4">
          {results.alive_subdomains?.length > 0 ? (
            <div className="bg-slate-700 rounded-lg p-4">
              <h3 className="font-bold text-white mb-4">✅ Alive Subdomains ({results.alive_subdomains.length})</h3>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {results.alive_subdomains.slice(0, 20).map((subdomain: string, i: number) => (
                  <div
                    key={i}
                    className="bg-slate-600 rounded px-3 py-2 font-mono text-sm text-slate-100"
                  >
                    {subdomain}
                  </div>
                ))}
                {results.alive_subdomains.length > 20 && (
                  <p className="text-slate-400 text-sm text-center">
                    ... and {results.alive_subdomains.length - 20} more
                  </p>
                )}
              </div>
            </div>
          ) : (
            <p className="text-slate-400">No live subdomains found</p>
          )}
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {results.vulnerabilities?.length > 0 ? (
            <div className="space-y-3">
              {results.vulnerabilities.slice(0, 20).map((vuln: any, i: number) => (
                <div
                  key={i}
                  className="bg-slate-700 rounded-lg p-4 cursor-pointer hover:bg-slate-600 transition-colors"
                  onClick={() => setExpandedVuln(expandedVuln === i ? null : i)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(vuln.risk_level)}`}>
                          {vuln.risk_level || 'UNKNOWN'}
                        </span>
                        <span className="text-white font-medium">{vuln.type || 'Unknown'}</span>
                      </div>
                      <p className="text-slate-400 text-sm">
                        <code className="text-blue-300">{vuln.endpoint || 'N/A'}</code>
                      </p>
                    </div>
                    <span className="text-slate-400">
                      {vuln.confidence && `${(vuln.confidence * 100).toFixed(0)}%`}
                    </span>
                  </div>

                  {expandedVuln === i && (
                    <div className="mt-3 pt-3 border-t border-slate-600 space-y-2 text-sm">
                      {vuln.parameter && (
                        <p><span className="text-slate-400">Parameter:</span> <code className="text-slate-300">{vuln.parameter}</code></p>
                      )}
                      {vuln.description && (
                        <p><span className="text-slate-400">Description:</span> {vuln.description}</p>
                      )}
                      {vuln.remediation && (
                        <p><span className="text-slate-400">Remediation:</span> {vuln.remediation}</p>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {results.vulnerabilities.length > 20 && (
                <p className="text-slate-400 text-center text-sm">
                  ... and {results.vulnerabilities.length - 20} more vulnerabilities
                </p>
              )}
            </div>
          ) : (
            <p className="text-slate-400">No vulnerabilities detected</p>
          )}
        </div>
      )}

      {/* Endpoints Tab */}
      {activeTab === 'endpoints' && (
        <div className="space-y-4">
          {Object.keys(results.endpoints || {}).length > 0 ? (
            <div className="bg-slate-700 rounded-lg p-4">
              <h3 className="font-bold text-white mb-4">🔗 Endpoints ({Object.keys(results.endpoints).length})</h3>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {Object.keys(results.endpoints)
                  .slice(0, 20)
                  .map((endpoint, i) => (
                    <div key={i} className="bg-slate-600 rounded px-3 py-2 font-mono text-sm text-slate-100">
                      {endpoint}
                    </div>
                  ))}
                {Object.keys(results.endpoints).length > 20 && (
                  <p className="text-slate-400 text-sm text-center">
                    ... and {Object.keys(results.endpoints).length - 20} more
                  </p>
                )}
              </div>
            </div>
          ) : (
            <p className="text-slate-400">No endpoints found</p>
          )}
        </div>
      )}

      <Button
        onClick={() => {
          // Download results as JSON
          const element = document.createElement('a');
          element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(JSON.stringify(results, null, 2)));
          element.setAttribute('download', `scan_results_${results.target}_${new Date().getTime()}.json`);
          element.style.display = 'none';
          document.body.appendChild(element);
          element.click();
          document.body.removeChild(element);
        }}
        className="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2 rounded-lg transition-all"
      >
        📥 Download Results as JSON
      </Button>
    </div>
  );
}
