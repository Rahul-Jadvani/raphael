import { json, type ActionFunctionArgs } from '@remix-run/node';

/*
 * ---------------------------------------------------------------------------
 * Interfaces – identical to ZAP scanner so the UI (ZapDialog, api.dast-pdf)
 * can consume the result unchanged.
 * ---------------------------------------------------------------------------
 */

interface ZapAlert {
  id: string;
  name: string;
  riskdesc: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: string;
  desc: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  instances: Array<{
    uri: string;
    method: string;
    param: string;
    attack: string;
    evidence: string;
  }>;
}

interface ZapScanResult {
  success: boolean;
  alerts: ZapAlert[];
  stats: {
    total: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  scanDuration: number;
  targetUrl: string;
  error?: string;
}

/*
 * ---------------------------------------------------------------------------
 * Helper – build a ZapAlert
 * ---------------------------------------------------------------------------
 */

let _alertCounter = 0;

function makeAlert(opts: {
  name: string;
  risk: ZapAlert['risk'];
  confidence: string;
  desc: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  uri: string;
  method?: string;
  param?: string;
  evidence?: string;
}): ZapAlert {
  _alertCounter++;

  const riskLabels: Record<string, string> = {
    High: 'High (3)',
    Medium: 'Medium (2)',
    Low: 'Low (1)',
    Informational: 'Informational (0)',
  };

  return {
    id: String(_alertCounter),
    name: opts.name,
    risk: opts.risk,
    riskdesc: riskLabels[opts.risk] ?? opts.risk,
    confidence: opts.confidence,
    desc: opts.desc,
    solution: opts.solution,
    reference: opts.reference,
    cweid: opts.cweid,
    wascid: opts.wascid,
    instances: [
      {
        uri: opts.uri,
        method: opts.method ?? 'GET',
        param: opts.param ?? '',
        attack: '',
        evidence: opts.evidence ?? '',
      },
    ],
  };
}

/*
 * ---------------------------------------------------------------------------
 * Individual checks
 * ---------------------------------------------------------------------------
 */

async function checkSecurityHeaders(url: string, headers: Headers): Promise<ZapAlert[]> {
  const alerts: ZapAlert[] = [];

  const headerChecks: Array<{
    header: string;
    name: string;
    risk: ZapAlert['risk'];
    cweid: string;
    wascid: string;
    desc: string;
    solution: string;
    reference: string;
  }> = [
    {
      header: 'content-security-policy',
      name: 'Missing Content Security Policy (CSP)',
      risk: 'Medium',
      cweid: '1021',
      wascid: '15',
      desc: 'Content Security Policy (CSP) header is not set. CSP helps prevent cross-site scripting (XSS), clickjacking, and other code-injection attacks by specifying which dynamic resources are allowed to load.',
      solution:
        'Set a Content-Security-Policy header with a strict policy that limits the sources of scripts, styles, images, and other resources.',
      reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      header: 'x-content-type-options',
      name: 'Missing X-Content-Type-Options Header',
      risk: 'Low',
      cweid: '693',
      wascid: '15',
      desc: 'The X-Content-Type-Options header is not set to "nosniff". This allows older browsers to MIME-sniff the response body, which may cause the response to be interpreted as a different content type.',
      solution: 'Set the X-Content-Type-Options header to "nosniff" for all responses.',
      reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      header: 'x-frame-options',
      name: 'Missing X-Frame-Options Header',
      risk: 'Medium',
      cweid: '1021',
      wascid: '15',
      desc: 'The X-Frame-Options header is not set. This can allow the page to be embedded in an iframe, making it vulnerable to clickjacking attacks.',
      solution: 'Set the X-Frame-Options header to DENY or SAMEORIGIN on all responses.',
      reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      header: 'strict-transport-security',
      name: 'Missing Strict-Transport-Security (HSTS) Header',
      risk: 'Low',
      cweid: '319',
      wascid: '15',
      desc: 'HTTP Strict Transport Security (HSTS) header is not set. This means the site does not enforce HTTPS connections and may be vulnerable to protocol downgrade attacks and cookie hijacking.',
      solution:
        'Add a Strict-Transport-Security header with a max-age of at least 31536000 (one year). Consider including "includeSubDomains" and "preload" directives.',
      reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    },
    {
      header: 'x-xss-protection',
      name: 'Missing X-XSS-Protection Header',
      risk: 'Low',
      cweid: '79',
      wascid: '14',
      desc: 'The X-XSS-Protection header is not set. While modern browsers have built-in XSS filters, this header provides an additional layer of defence for older browsers.',
      solution: 'Set the X-XSS-Protection header to "1; mode=block".',
      reference: 'https://owasp.org/Top10/A03_2021-Injection/',
    },
    {
      header: 'referrer-policy',
      name: 'Missing Referrer-Policy Header',
      risk: 'Low',
      cweid: '116',
      wascid: '15',
      desc: 'The Referrer-Policy header is not set. This may leak referrer information when navigating to external sites.',
      solution: 'Set the Referrer-Policy header to "strict-origin-when-cross-origin" or "no-referrer".',
      reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
    {
      header: 'permissions-policy',
      name: 'Missing Permissions-Policy Header',
      risk: 'Low',
      cweid: '693',
      wascid: '15',
      desc: 'The Permissions-Policy (formerly Feature-Policy) header is not set. This header controls which browser features the site is allowed to use (camera, microphone, geolocation, etc.).',
      solution: 'Set a Permissions-Policy header to disable unnecessary browser features.',
      reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    },
  ];

  for (const check of headerChecks) {
    const value = headers.get(check.header);

    if (!value) {
      alerts.push(
        makeAlert({
          name: check.name,
          risk: check.risk,
          confidence: 'High',
          desc: check.desc,
          solution: check.solution,
          reference: check.reference,
          cweid: check.cweid,
          wascid: check.wascid,
          uri: url,
          evidence: `Header "${check.header}" is missing from the response.`,
        }),
      );
    }
  }

  // Extra: check CSP frame-ancestors for clickjacking
  const csp = headers.get('content-security-policy') ?? '';
  const xfo = headers.get('x-frame-options');

  if (csp && !csp.includes('frame-ancestors') && !xfo) {
    alerts.push(
      makeAlert({
        name: 'Clickjacking: CSP frame-ancestors Missing',
        risk: 'Medium',
        confidence: 'Medium',
        desc: 'A Content-Security-Policy header is present but does not include the frame-ancestors directive, and no X-Frame-Options header is set. The page may be vulnerable to clickjacking.',
        solution: 'Add "frame-ancestors \'self\'" (or more restrictive) to the Content-Security-Policy header.',
        reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
        cweid: '1021',
        wascid: '15',
        uri: url,
        evidence: 'CSP present without frame-ancestors directive.',
      }),
    );
  }

  return alerts;
}

function checkCookieSecurity(url: string, headers: Headers): ZapAlert[] {
  const alerts: ZapAlert[] = [];
  const setCookies = headers.getSetCookie?.() ?? [];

  // Fallback: some runtimes expose set-cookie as a single comma-joined string
  const cookieHeaders =
    setCookies.length > 0 ? setCookies : (headers.get('set-cookie') ?? '').split(/,(?=\s*\w+=)/).filter(Boolean);

  for (const cookie of cookieHeaders) {
    const cookieName = cookie.split('=')[0]?.trim() ?? 'unknown';
    const lower = cookie.toLowerCase();

    if (!lower.includes('secure')) {
      alerts.push(
        makeAlert({
          name: 'Cookie Without Secure Flag',
          risk: 'Low',
          confidence: 'High',
          desc: `The cookie "${cookieName}" does not have the Secure flag set. It may be transmitted over unencrypted HTTP connections.`,
          solution: 'Add the "Secure" flag to all cookies, especially those containing session tokens.',
          reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
          cweid: '614',
          wascid: '13',
          uri: url,
          param: cookieName,
          evidence: cookie.trim(),
        }),
      );
    }

    if (!lower.includes('httponly')) {
      alerts.push(
        makeAlert({
          name: 'Cookie Without HttpOnly Flag',
          risk: 'Low',
          confidence: 'High',
          desc: `The cookie "${cookieName}" does not have the HttpOnly flag set. It can be accessed via JavaScript, increasing the risk of session theft through XSS.`,
          solution: 'Add the "HttpOnly" flag to cookies that do not need to be accessed from client-side JavaScript.',
          reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
          cweid: '1004',
          wascid: '13',
          uri: url,
          param: cookieName,
          evidence: cookie.trim(),
        }),
      );
    }

    if (!lower.includes('samesite')) {
      alerts.push(
        makeAlert({
          name: 'Cookie Without SameSite Attribute',
          risk: 'Low',
          confidence: 'High',
          desc: `The cookie "${cookieName}" does not have the SameSite attribute set. This may make it vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
          solution: 'Set the SameSite attribute to "Strict" or "Lax" on all cookies.',
          reference: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
          cweid: '1275',
          wascid: '13',
          uri: url,
          param: cookieName,
          evidence: cookie.trim(),
        }),
      );
    }
  }

  return alerts;
}

function checkServerDisclosure(url: string, headers: Headers): ZapAlert[] {
  const alerts: ZapAlert[] = [];

  const disclosureHeaders: Array<{ header: string; label: string }> = [
    { header: 'server', label: 'Server' },
    { header: 'x-powered-by', label: 'X-Powered-By' },
    { header: 'x-aspnet-version', label: 'X-AspNet-Version' },
  ];

  for (const { header, label } of disclosureHeaders) {
    const value = headers.get(header);

    if (value) {
      alerts.push(
        makeAlert({
          name: `${label} Header Information Leak`,
          risk: 'Low',
          confidence: 'High',
          desc: `The "${label}" header discloses server-side technology information ("${value}"). This can help an attacker fingerprint the server and target known vulnerabilities.`,
          solution: `Remove or suppress the "${label}" header in production.`,
          reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
          cweid: '200',
          wascid: '13',
          uri: url,
          evidence: `${label}: ${value}`,
        }),
      );
    }
  }

  return alerts;
}

async function checkSensitiveFiles(baseUrl: string): Promise<ZapAlert[]> {
  const alerts: ZapAlert[] = [];

  const sensitiveFiles: Array<{
    path: string;
    name: string;
    desc: string;
    cweid: string;
  }> = [
    {
      path: '/.env',
      name: 'Environment File Exposed (.env)',
      desc: 'The .env file is publicly accessible. It often contains secrets such as database credentials, API keys, and internal service URLs.',
      cweid: '215',
    },
    {
      path: '/.git/config',
      name: 'Git Configuration Exposed (.git/config)',
      desc: 'The Git configuration file is publicly accessible. This can reveal the repository URL, branch information, and potentially developer identities.',
      cweid: '215',
    },
    {
      path: '/wp-admin',
      name: 'WordPress Admin Panel Accessible',
      desc: 'The WordPress admin panel is accessible. If not properly secured, this can be a target for brute-force and credential-stuffing attacks.',
      cweid: '200',
    },
    {
      path: '/.DS_Store',
      name: 'macOS .DS_Store File Exposed',
      desc: 'A macOS .DS_Store file is publicly accessible. This file can reveal directory structure and file names on the server.',
      cweid: '538',
    },
    {
      path: '/server-status',
      name: 'Apache Server Status Page Exposed',
      desc: 'The Apache server-status page is publicly accessible. It reveals detailed information about current server load, request processing, and client connections.',
      cweid: '200',
    },
  ];

  const probes = sensitiveFiles.map(async (file) => {
    try {
      const probeUrl = new URL(file.path, baseUrl).toString();
      const resp = await fetch(probeUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(5000),
        headers: { 'User-Agent': 'Raphael-DAST-Scanner/1.0' },
      });

      // Consider 200 and 403 as noteworthy (403 means the path exists but is blocked)
      if (resp.status === 200) {
        const body = await resp.text();

        // Heuristic: skip obvious custom 404 pages that return 200
        const is404Page = body.length < 2000 && (/not\s*found/i.test(body) || /404/i.test(body));

        if (!is404Page) {
          alerts.push(
            makeAlert({
              name: file.name,
              risk: 'High',
              confidence: 'Medium',
              desc: file.desc,
              solution:
                'Restrict access to this file/path. Remove it from the web root or block it via server configuration.',
              reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
              cweid: file.cweid,
              wascid: '13',
              uri: probeUrl,
              evidence: `HTTP ${resp.status} — response body length ${body.length} bytes`,
            }),
          );
        }
      }
    } catch {
      // Timeout / network error — silently skip
    }
  });

  await Promise.all(probes);

  return alerts;
}

async function checkCorsMisconfiguration(url: string): Promise<ZapAlert[]> {
  const alerts: ZapAlert[] = [];

  try {
    const resp = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(5000),
      headers: {
        'User-Agent': 'Raphael-DAST-Scanner/1.0',
        Origin: 'https://evil.example.com',
      },
    });

    const acao = resp.headers.get('access-control-allow-origin');

    if (acao === '*') {
      alerts.push(
        makeAlert({
          name: 'CORS Wildcard Access-Control-Allow-Origin',
          risk: 'Medium',
          confidence: 'High',
          desc: 'The server responds with Access-Control-Allow-Origin: *, allowing any website to make cross-origin requests and read the response. If the application exposes sensitive data, this is a significant risk.',
          solution:
            'Restrict CORS to a whitelist of trusted origins instead of using a wildcard. Avoid reflecting the Origin header blindly.',
          reference: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
          cweid: '942',
          wascid: '14',
          uri: url,
          evidence: `Access-Control-Allow-Origin: ${acao}`,
        }),
      );
    } else if (acao === 'https://evil.example.com') {
      alerts.push(
        makeAlert({
          name: 'CORS Origin Reflection Misconfiguration',
          risk: 'High',
          confidence: 'High',
          desc: 'The server reflects the supplied Origin header in the Access-Control-Allow-Origin response, trusting any origin. An attacker can exploit this to steal sensitive data from authenticated users via a malicious website.',
          solution:
            'Validate the Origin header against a strict whitelist of trusted domains. Never blindly reflect the Origin.',
          reference: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
          cweid: '942',
          wascid: '14',
          uri: url,
          evidence: `Access-Control-Allow-Origin: ${acao} (reflected from evil.example.com)`,
        }),
      );
    }

    const acac = resp.headers.get('access-control-allow-credentials');

    if (acac === 'true' && (acao === '*' || acao === 'https://evil.example.com')) {
      alerts.push(
        makeAlert({
          name: 'CORS Allows Credentials with Permissive Origin',
          risk: 'High',
          confidence: 'High',
          desc: 'The server allows credentials (cookies, authorization headers) in cross-origin requests while also permitting a wide or reflected origin. This combination makes it trivial for an attacker to exfiltrate authenticated data.',
          solution:
            'Never combine Access-Control-Allow-Credentials: true with a wildcard or reflected origin. Use a strict origin whitelist.',
          reference: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
          cweid: '942',
          wascid: '14',
          uri: url,
          evidence: `Access-Control-Allow-Credentials: true with ACAO: ${acao}`,
        }),
      );
    }
  } catch {
    // Network / timeout error — skip
  }

  return alerts;
}

async function checkHttpsEnforcement(url: string): Promise<ZapAlert[]> {
  const alerts: ZapAlert[] = [];

  try {
    const parsed = new URL(url);

    // Only meaningful if the target is HTTPS — see if an HTTP variant exists
    if (parsed.protocol === 'https:') {
      const httpUrl = url.replace(/^https:/, 'http:');

      try {
        const resp = await fetch(httpUrl, {
          method: 'HEAD',
          redirect: 'manual', // don't follow — we want to see the redirect itself
          signal: AbortSignal.timeout(5000),
          headers: { 'User-Agent': 'Raphael-DAST-Scanner/1.0' },
        });

        const location = resp.headers.get('location') ?? '';
        const redirectsToHttps = location.startsWith('https://');

        if (resp.status >= 200 && resp.status < 400 && !redirectsToHttps) {
          alerts.push(
            makeAlert({
              name: 'HTTP Does Not Redirect to HTTPS',
              risk: 'Medium',
              confidence: 'High',
              desc: 'The HTTP version of the site responds without redirecting to HTTPS. Users or automated tools that access the HTTP URL will communicate over an unencrypted channel.',
              solution: 'Configure the server to issue a 301 redirect from HTTP to HTTPS for all routes.',
              reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
              cweid: '319',
              wascid: '15',
              uri: httpUrl,
              evidence: `HTTP ${resp.status} — Location: ${location || '(none)'}`,
            }),
          );
        }
      } catch {
        // HTTP port may not be open — that is fine, nothing to report
      }
    }

    // If the target itself is HTTP, flag it
    if (parsed.protocol === 'http:') {
      alerts.push(
        makeAlert({
          name: 'Target URL Uses Unencrypted HTTP',
          risk: 'Medium',
          confidence: 'High',
          desc: 'The target URL uses plain HTTP. All communication, including credentials and sensitive data, is transmitted without encryption and can be intercepted.',
          solution:
            "Serve the site over HTTPS. Obtain a TLS certificate (e.g., via Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
          reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
          cweid: '319',
          wascid: '15',
          uri: url,
          evidence: 'URL scheme is http://',
        }),
      );
    }
  } catch {
    // Malformed URL — handled elsewhere
  }

  return alerts;
}

/*
 * ---------------------------------------------------------------------------
 * GET loader — availability check
 * ---------------------------------------------------------------------------
 */

export async function loader() {
  return json({ available: true, message: 'Quick DAST scanner available' });
}

/*
 * ---------------------------------------------------------------------------
 * POST action — run the scan
 * ---------------------------------------------------------------------------
 */

export async function action({ request }: ActionFunctionArgs) {
  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, { status: 405 });
  }

  const startTime = Date.now();

  // Reset per-request counter
  _alertCounter = 0;

  try {
    const body = (await request.json()) as { targetUrl?: string };
    const targetUrl = body.targetUrl?.trim();

    // ---- Validate URL ----
    if (!targetUrl) {
      return json(
        {
          success: false,
          alerts: [],
          stats: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanDuration: 0,
          targetUrl: '',
          error: 'targetUrl is required',
        } satisfies ZapScanResult,
        { status: 400 },
      );
    }

    let parsed: URL;

    try {
      parsed = new URL(targetUrl);
    } catch {
      return json(
        {
          success: false,
          alerts: [],
          stats: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanDuration: 0,
          targetUrl,
          error: 'Invalid URL format',
        } satisfies ZapScanResult,
        { status: 400 },
      );
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return json(
        {
          success: false,
          alerts: [],
          stats: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanDuration: 0,
          targetUrl,
          error: 'Only http and https URLs are supported',
        } satisfies ZapScanResult,
        { status: 400 },
      );
    }

    // ---- Check reachability ----
    let mainResponse: Response;

    try {
      mainResponse = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(10000),
        headers: { 'User-Agent': 'Raphael-DAST-Scanner/1.0' },
      });
    } catch (err: any) {
      return json(
        {
          success: false,
          alerts: [],
          stats: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanDuration: Date.now() - startTime,
          targetUrl,
          error: `Target unreachable: ${err?.message ?? 'connection failed'}`,
        } satisfies ZapScanResult,
        { status: 502 },
      );
    }

    // ---- Run all checks in parallel ----
    const [headerAlerts, cookieAlerts, serverAlerts, sensitiveAlerts, corsAlerts, httpsAlerts] = await Promise.all([
      checkSecurityHeaders(targetUrl, mainResponse.headers),
      checkCookieSecurity(targetUrl, mainResponse.headers),
      checkServerDisclosure(targetUrl, mainResponse.headers),
      checkSensitiveFiles(targetUrl),
      checkCorsMisconfiguration(targetUrl),
      checkHttpsEnforcement(targetUrl),
    ]);

    const alerts: ZapAlert[] = [
      ...headerAlerts,
      ...cookieAlerts,
      ...serverAlerts,
      ...sensitiveAlerts,
      ...corsAlerts,
      ...httpsAlerts,
    ];

    // Re-number IDs sequentially
    alerts.forEach((a, i) => {
      a.id = String(i + 1);
    });

    const stats = {
      total: alerts.length,
      high: alerts.filter((a) => a.risk === 'High').length,
      medium: alerts.filter((a) => a.risk === 'Medium').length,
      low: alerts.filter((a) => a.risk === 'Low').length,
      info: alerts.filter((a) => a.risk === 'Informational').length,
    };

    const result: ZapScanResult = {
      success: true,
      alerts,
      stats,
      scanDuration: Date.now() - startTime,
      targetUrl,
    };

    console.log(
      `[DAST-Scan] Completed scan of ${targetUrl} in ${result.scanDuration}ms — ` +
        `${stats.total} findings (H:${stats.high} M:${stats.medium} L:${stats.low} I:${stats.info})`,
    );

    return json(result);
  } catch (err: any) {
    console.error('[DAST-Scan] Unexpected error:', err);

    return json(
      {
        success: false,
        alerts: [],
        stats: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
        scanDuration: Date.now() - startTime,
        targetUrl: '',
        error: err?.message ?? 'Internal scanner error',
      } satisfies ZapScanResult,
      { status: 500 },
    );
  }
}
