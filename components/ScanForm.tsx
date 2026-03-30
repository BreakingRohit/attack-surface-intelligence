'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';

interface ScanFormProps {
  onScanStart: () => void;
  onScanComplete: (results: any) => void;
}

export default function ScanForm({ onScanStart, onScanComplete }: ScanFormProps) {
  const [target, setTarget] = useState('');
  const [subdomainWordlist, setSubdomainWordlist] = useState('default');
  const [directoryWordlist, setDirectoryWordlist] = useState('default');
  const [wordlists, setWordlists] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [threads, setThreads] = useState(25);
  const [timeout, setTimeout] = useState(4);

  // Load available wordlists
  useEffect(() => {
    const loadWordlists = async () => {
      try {
        const response = await fetch('http://localhost:8000/wordlists');
        const data = await response.json();
        setWordlists(data.wordlists || []);
      } catch (err) {
        console.error('Error loading wordlists:', err);
      }
    };

    loadWordlists();
    const interval = setInterval(loadWordlists, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!target.trim()) {
      setError('Target domain is required');
      return;
    }

    setLoading(true);
    onScanStart();

    try {
      // Start scan
      const scanResponse = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          subdomain_wordlist: subdomainWordlist,
          directory_wordlist: directoryWordlist,
          threads,
          timeout,
          verbose: false,
        }),
      });

      if (!scanResponse.ok) {
        throw new Error('Failed to start scan');
      }

      const scanData = await scanResponse.json();
      const scanId = scanData.scan_id;

      // Poll for results
      let completed = false;
      let attempts = 0;
      const maxAttempts = 300; // 5 minutes with 1-second intervals

      while (!completed && attempts < maxAttempts) {
        const statusResponse = await fetch(`http://localhost:8000/scan/${scanId}`);
        const statusData = await statusResponse.json();

        if (statusData.status === 'completed') {
          // Fetch full results
          const resultsResponse = await fetch(`http://localhost:8000/scan/${scanId}/results`);
          const results = await resultsResponse.json();
          onScanComplete(results);
          completed = true;
        } else if (statusData.status === 'failed') {
          setError(`Scan failed: ${statusData.error}`);
          completed = true;
        }

        if (!completed) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          attempts++;
        }
      }

      if (!completed) {
        setError('Scan timeout');
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          Target Domain
        </label>
        <Input
          type="text"
          placeholder="example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={loading}
          className="bg-slate-700 border-slate-600 text-white placeholder-slate-400"
        />
        <p className="text-xs text-slate-500 mt-1">Enter the domain you want to scan</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Subdomain Wordlist
          </label>
          <select
            value={subdomainWordlist}
            onChange={(e) => setSubdomainWordlist(e.target.value)}
            disabled={loading}
            className="w-full bg-slate-700 border border-slate-600 rounded-md px-3 py-2 text-white hover:border-slate-500 focus:outline-none focus:border-blue-500"
          >
            <option value="default">Default Wordlist</option>
            {wordlists.map((wl) => (
              <option key={wl} value={wl}>
                {wl.substring(0, 50)}...
              </option>
            ))}
          </select>
          <p className="text-xs text-slate-500 mt-1">
            {subdomainWordlist === 'default' 
              ? 'Using default subdomain list' 
              : `Using custom wordlist: ${subdomainWordlist}`}
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Directory Wordlist
          </label>
          <select
            value={directoryWordlist}
            onChange={(e) => setDirectoryWordlist(e.target.value)}
            disabled={loading}
            className="w-full bg-slate-700 border border-slate-600 rounded-md px-3 py-2 text-white hover:border-slate-500 focus:outline-none focus:border-blue-500"
          >
            <option value="default">Default Wordlist</option>
            {wordlists.map((wl) => (
              <option key={wl} value={wl}>
                {wl.substring(0, 50)}...
              </option>
            ))}
          </select>
          <p className="text-xs text-slate-500 mt-1">
            {directoryWordlist === 'default'
              ? 'Using default directory list'
              : `Using custom wordlist: ${directoryWordlist}`}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Threads ({threads})
          </label>
          <input
            type="range"
            min="5"
            max="50"
            value={threads}
            onChange={(e) => setThreads(parseInt(e.target.value))}
            disabled={loading}
            className="w-full"
          />
          <p className="text-xs text-slate-500 mt-1">Higher = faster but more resource intensive</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Timeout (seconds)
          </label>
          <input
            type="number"
            min="1"
            max="30"
            value={timeout}
            onChange={(e) => setTimeout(parseInt(e.target.value))}
            disabled={loading}
            className="w-full bg-slate-700 border border-slate-600 rounded-md px-3 py-2 text-white"
          />
          <p className="text-xs text-slate-500 mt-1">Request timeout in seconds</p>
        </div>
      </div>

      {error && (
        <div className="bg-red-900 border border-red-700 text-red-100 px-4 py-3 rounded-md">
          {error}
        </div>
      )}

      <Button
        type="submit"
        disabled={loading}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 rounded-lg transition-all"
      >
        {loading ? 'Scanning...' : 'Start Scan'}
      </Button>
    </form>
  );
}
