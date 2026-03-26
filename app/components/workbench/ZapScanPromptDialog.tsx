import { memo, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';

type ScanMode = 'quick' | 'deep';

interface ZapScanPromptDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onStartScan: (config: { autoDeploy: boolean; manualUrl?: string; scanMode: ScanMode }) => void;
}

export const ZapScanPromptDialog = memo(({ isOpen, onClose, onStartScan }: ZapScanPromptDialogProps) => {
  const [targetUrl, setTargetUrl] = useState('https://');
  const [urlError, setUrlError] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('quick');

  const handleStartScan = () => {
    // Validate URL
    if (!targetUrl || (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://'))) {
      setUrlError('Please enter a valid URL starting with http:// or https://');
      return;
    }

    if (targetUrl === 'https://' || targetUrl === 'http://') {
      setUrlError('Please enter a complete URL');
      return;
    }

    onStartScan({ autoDeploy: false, manualUrl: targetUrl, scanMode });
    onClose();
  };

  const handleCancel = () => {
    setTargetUrl('https://');
    setUrlError('');
    setScanMode('quick');
    onClose();
  };

  return (
    <Dialog.Root open={isOpen} onOpenChange={handleCancel}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[90vw] max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-lg bg-bolt-elements-background-depth-2 shadow-2xl border border-bolt-elements-borderColor">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-bolt-elements-borderColor bg-bolt-elements-background-depth-1">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
                <div className="i-ph:shield-warning text-white text-2xl" />
              </div>
              <div>
                <Dialog.Title className="text-lg font-semibold text-bolt-elements-textPrimary">
                  Configure DAST Scan
                </Dialog.Title>
                <Dialog.Description className="text-sm text-bolt-elements-textSecondary mt-0.5">
                  Choose how to scan your application for security vulnerabilities
                </Dialog.Description>
              </div>
            </div>
            <button
              onClick={handleCancel}
              className="text-bolt-elements-textSecondary hover:text-bolt-elements-textPrimary transition-colors rounded-lg p-2 hover:bg-bolt-elements-background-depth-3"
            >
              <div className="i-ph:x text-xl" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* Scan Mode Toggle */}
            <div className="space-y-3">
              <label className="block text-sm font-medium text-bolt-elements-textPrimary">Scan Mode</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => setScanMode('quick')}
                  className={`p-4 rounded-lg border-2 transition-all text-left ${
                    scanMode === 'quick'
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-bolt-elements-borderColor bg-bolt-elements-background-depth-1 hover:border-blue-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className="i-ph:lightning text-blue-400 text-lg" />
                    <span className="font-medium text-bolt-elements-textPrimary text-sm">Quick Scan</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/20 text-green-400 font-medium">
                      Recommended
                    </span>
                  </div>
                  <p className="text-xs text-bolt-elements-textSecondary">
                    Node.js native scanner. No Docker needed. Checks security headers, cookies, CORS, sensitive files,
                    and more.
                  </p>
                  <p className="text-xs text-bolt-elements-textTertiary mt-1">~5-15 seconds</p>
                </button>
                <button
                  onClick={() => setScanMode('deep')}
                  className={`p-4 rounded-lg border-2 transition-all text-left ${
                    scanMode === 'deep'
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-bolt-elements-borderColor bg-bolt-elements-background-depth-1 hover:border-blue-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className="i-ph:shield-check text-cyan-400 text-lg" />
                    <span className="font-medium text-bolt-elements-textPrimary text-sm">Deep Scan</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-medium">
                      Docker Required
                    </span>
                  </div>
                  <p className="text-xs text-bolt-elements-textSecondary">
                    OWASP ZAP baseline scan via Docker. Comprehensive active + passive scanning with spider crawling.
                  </p>
                  <p className="text-xs text-bolt-elements-textTertiary mt-1">~5-10 minutes</p>
                </button>
              </div>
            </div>

            {/* URL Input */}
            <div className="space-y-3">
              <label className="block text-sm font-medium text-bolt-elements-textPrimary">
                {scanMode === 'quick' ? 'Target URL' : 'Deployment URL'}
              </label>
              <div className="relative">
                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-bolt-elements-textSecondary">
                  <div className="i-ph:globe text-lg" />
                </div>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => {
                    setTargetUrl(e.target.value);
                    setUrlError('');
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      handleStartScan();
                    }
                  }}
                  placeholder="https://your-app.vercel.app"
                  className="w-full pl-10 pr-4 py-3 rounded-lg bg-bolt-elements-background-depth-1 border border-bolt-elements-borderColor text-bolt-elements-textPrimary placeholder-bolt-elements-textTertiary focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
                  autoFocus
                />
              </div>
              {urlError && (
                <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                  <div className="i-ph:warning-circle text-lg" />
                  {urlError}
                </div>
              )}
              <div className="space-y-2">
                <p className="text-xs text-bolt-elements-textSecondary">
                  <span className="font-medium text-bolt-elements-textPrimary">Supported platforms:</span> Vercel,
                  Netlify, Railway, Render, or any publicly accessible URL
                </p>
                <div className="flex flex-wrap gap-2">
                  <code className="px-2 py-1 text-xs bg-bolt-elements-background-depth-1 border border-bolt-elements-borderColor rounded">
                    https://app.vercel.app
                  </code>
                  <code className="px-2 py-1 text-xs bg-bolt-elements-background-depth-1 border border-bolt-elements-borderColor rounded">
                    https://staging.mysite.com
                  </code>
                </div>
              </div>
            </div>

            {/* Info Box */}
            <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/30">
              <div className="flex items-start gap-3">
                <div className="i-ph:info text-blue-400 text-xl mt-0.5" />
                <div className="flex-1">
                  <h4 className="text-sm font-medium text-bolt-elements-textPrimary mb-1">
                    {scanMode === 'quick' ? 'About Quick Scan' : 'About Deep Scan'}
                  </h4>
                  <p className="text-xs text-bolt-elements-textSecondary">
                    {scanMode === 'quick'
                      ? 'Quick Scan uses a lightweight Node.js scanner to check for security headers, cookie security, server disclosure, sensitive file exposure, CORS misconfiguration, and HTTPS enforcement. Findings include CWE IDs and OWASP Top 10 references.'
                      : 'Deep Scan uses OWASP ZAP via Docker to perform comprehensive active and passive security testing including spider crawling, SQL injection, XSS, and more. Requires Docker Desktop to be running.'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-bolt-elements-borderColor bg-bolt-elements-background-depth-1">
            <button
              onClick={handleCancel}
              className="px-4 py-2 rounded-lg text-sm font-medium text-bolt-elements-textPrimary bg-bolt-elements-background-depth-3 hover:bg-bolt-elements-background-depth-2 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleStartScan}
              className="px-5 py-2 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 shadow-lg shadow-blue-500/25 transition-all flex items-center gap-2"
            >
              <div className="i-ph:play-circle" />
              Start {scanMode === 'quick' ? 'Quick' : 'Deep'} Scan
              <span className="text-xs opacity-75">({scanMode === 'quick' ? '~15 sec' : '~5-10 min'})</span>
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
});

ZapScanPromptDialog.displayName = 'ZapScanPromptDialog';
