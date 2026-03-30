'use client';

import { useState } from 'react';
import ScanForm from '@/components/ScanForm';
import ScanResults from '@/components/ScanResults';
import WordlistManager from '@/components/WordlistManager';
import { Card } from '@/components/ui/card';

export default function Home() {
  const [activeTab, setActiveTab] = useState<'scan' | 'wordlists'>('scan');
  const [scanResults, setScanResults] = useState(null);
  const [scanInProgress, setScanInProgress] = useState(false);

  const handleScanStart = () => {
    setScanInProgress(true);
  };

  const handleScanComplete = (results: any) => {
    setScanResults(results);
    setScanInProgress(false);
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">🔒 Attack Surface Intelligence</h1>
          <p className="text-slate-400">Professional reconnaissance and vulnerability assessment framework</p>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-4 mb-8">
          <button
            onClick={() => setActiveTab('scan')}
            className={`px-6 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'scan'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            Scan
          </button>
          <button
            onClick={() => setActiveTab('wordlists')}
            className={`px-6 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'wordlists'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
          >
            Wordlists
          </button>
        </div>

        {/* Content */}
        <div className="grid gap-8">
          {activeTab === 'scan' ? (
            <>
              <Card className="border-slate-700 bg-slate-800">
                <div className="p-6">
                  <ScanForm
                    onScanStart={handleScanStart}
                    onScanComplete={handleScanComplete}
                  />
                </div>
              </Card>

              {scanResults && !scanInProgress && (
                <Card className="border-slate-700 bg-slate-800">
                  <div className="p-6">
                    <ScanResults results={scanResults} />
                  </div>
                </Card>
              )}

              {scanInProgress && (
                <Card className="border-slate-700 bg-slate-800">
                  <div className="p-12 text-center">
                    <div className="inline-block animate-spin mb-4">
                      <div className="w-12 h-12 border-4 border-slate-600 border-t-blue-500 rounded-full"></div>
                    </div>
                    <p className="text-slate-300">Scan in progress...</p>
                  </div>
                </Card>
              )}
            </>
          ) : (
            <Card className="border-slate-700 bg-slate-800">
              <div className="p-6">
                <WordlistManager />
              </div>
            </Card>
          )}
        </div>
      </div>
    </main>
  );
}
