'use client';

import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

interface Wordlist {
  filename: string;
  entries: number;
  size: number;
  uploadedAt?: string;
}

export default function WordlistManager() {
  const [wordlists, setWordlists] = useState<Wordlist[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadWordlists = async () => {
    setLoading(true);
    try {
      const response = await fetch('https://attack-surface-intelligence.onrender.com/wordlists');
      const data = await response.json();
      setWordlists(
        data.wordlists?.map((filename: string) => ({
          filename,
          entries: 0,
          size: 0,
        })) || []
      );
    } catch (err) {
      setError('Failed to load wordlists');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadWordlists();
  }, []);

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file
    if (!file.name.endsWith('.txt')) {
      setError('Only .txt files are allowed');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setError('File is too large (max 10MB)');
      return;
    }

    setError('');
    setSuccess('');
    setUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('https://attack-surface-intelligence.onrender.com/upload-wordlist', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Upload failed');
      }

      const data = await response.json();
      setSuccess(`✓ Uploaded "${file.name}" with ${data.entries} unique entries`);

      // Reload wordlists
      await loadWordlists();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-blue-900 to-blue-800 border border-blue-700 rounded-lg p-6">
        <h2 className="text-2xl font-bold text-white mb-2">📚 Custom Wordlist Manager</h2>
        <p className="text-blue-100 text-sm">
          Upload custom wordlists for subdomain and directory discovery. Max 10,000 entries per file.
        </p>
      </div>

      {/* Upload Section */}
      <Card className="border-slate-700 bg-slate-800">
        <div className="p-6">
          <div
            className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-blue-500 transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt"
              onChange={handleFileSelect}
              disabled={uploading}
              className="hidden"
            />

            <div className="text-4xl mb-3">📤</div>
            <p className="text-white font-medium mb-1">
              {uploading ? 'Uploading...' : 'Click to upload or drag and drop'}
            </p>
            <p className="text-slate-400 text-sm">
              .txt files only • Max 10MB • Max 10,000 entries
            </p>
          </div>

          {error && (
            <div className="mt-4 bg-red-900 border border-red-700 text-red-100 px-4 py-3 rounded-md">
              {error}
            </div>
          )}

          {success && (
            <div className="mt-4 bg-green-900 border border-green-700 text-green-100 px-4 py-3 rounded-md">
              {success}
            </div>
          )}
        </div>
      </Card>

      {/* Uploaded Wordlists */}
      {wordlists.length > 0 && (
        <Card className="border-slate-700 bg-slate-800">
          <div className="p-6">
            <h3 className="text-lg font-bold text-white mb-4">Uploaded Wordlists ({wordlists.length})</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {wordlists.map((wl) => (
                <div
                  key={wl.filename}
                  className="flex items-center justify-between bg-slate-700 rounded-lg p-3 hover:bg-slate-600 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-white font-medium truncate">{wl.filename}</p>
                    <p className="text-slate-400 text-sm">
                      Available for use in scans
                    </p>
                  </div>
                  <div className="text-right ml-4">
                    <p className="text-slate-300 text-sm font-mono">
                      {wl.filename.substring(0, 20)}...
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}

      {!loading && wordlists.length === 0 && !uploading && (
        <Card className="border-slate-700 bg-slate-700/50">
          <div className="p-8 text-center">
            <p className="text-slate-400">No custom wordlists uploaded yet</p>
            <p className="text-slate-500 text-sm mt-1">
              Upload wordlists to use them in your scans
            </p>
          </div>
        </Card>
      )}

      <div className="bg-slate-700 rounded-lg p-4">
        <h4 className="font-bold text-white mb-2">💡 Tips</h4>
        <ul className="text-slate-300 text-sm space-y-1">
          <li>• Each file should contain one entry per line</li>
          <li>• Duplicate entries are automatically removed</li>
          <li>• Empty lines are ignored</li>
          <li>• Files are automatically validated before upload</li>
        </ul>
      </div>
    </div>
  );
}
