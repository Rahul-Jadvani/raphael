<p align="center">
  <img src="public/logo-light-styled.png" alt="Raphael" width="200" />
</p>

<h1 align="center">RAPHAEL</h1>

<p align="center">
  <strong>AI-Powered Full-Stack Development Agent with Built-In Security Scanning</strong>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#security-scanners">Security Scanners</a> &bull;
  <a href="#getting-started">Getting Started</a> &bull;
  <a href="#deployment">Deployment</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#license">License</a>
</p>

---

## What is Raphael?

Raphael is an AI-powered coding agent that runs entirely in the browser. It generates, runs, and previews full-stack applications using an in-browser [WebContainer](https://webcontainers.io) runtime — no local server required. It ships with a complete security toolkit (SAST, DAST, Secrets, Dependency scanning) and cross-session memory so the AI remembers your preferences across conversations.

### Key Highlights

- **Full-stack in the browser** — Write, build, and preview React, Next.js, Vue, Svelte, and more without leaving the tab
- **Multi-provider AI** — Supports OpenAI, Anthropic, Google Gemini, Mistral, DeepSeek, Groq, Cohere, OpenRouter, and more
- **4 security scanners** — SAST (Semgrep), DAST (Quick Scan + OWASP ZAP), Secrets (GitLeaks), Dependencies (OSV)
- **PDF reports** — Every scanner generates downloadable PDF reports with CWE IDs and OWASP references
- **Persistent memory** — Mem0 integration remembers project context across sessions and model switches
- **One-click deploy** — Ship to Vercel or Netlify directly from the workbench
- **Desktop app** — Also available as an Electron app for Windows, macOS, and Linux

---

## Features

### AI Code Generation
- Chat-driven development with build and discuss modes
- Automatic starter template selection based on your prompt
- Prompt enhancement for better AI output
- File diffing and inline editing in the workbench
- Web search integration for up-to-date context

### In-Browser Runtime
- Full Node.js environment via WebContainer
- Integrated terminal (xterm.js) with multiple tabs
- Live preview with hot reload
- File system with CodeMirror editor (syntax highlighting for 10+ languages)

### Multi-Provider Support
| Provider | Models |
|----------|--------|
| OpenAI | GPT-4o, GPT-4o-mini, o1, o3-mini |
| Anthropic | Claude 3.5 Sonnet, Claude 3 Opus/Haiku |
| Google | Gemini 2.0 Flash, Gemini Pro |
| Mistral | Mistral Large, Codestral |
| DeepSeek | DeepSeek Chat, DeepSeek Reasoner |
| Groq | Llama 3, Mixtral |
| Cohere | Command R+ |
| OpenRouter | Any model via OpenRouter |
| Amazon Bedrock | Via AWS credentials |
| Ollama | Local models |
| LMStudio | Local models |

### Deployment
- **Vercel** — One-click deploy with auto-configuration
- **Netlify** — Direct deployment from the workbench
- **GitHub** — Push to any repository with branch selection

### Integrations
- **Supabase** — Connect databases, run queries, manage tables
- **GitHub / GitLab** — Import repos, browse branches, push code
- **MCP (Model Context Protocol)** — Extend with custom tool servers

---

## Security Scanners

Raphael includes four integrated security scanners accessible from the workbench toolbar. Every scanner produces findings with industry-standard identifiers (CWE, OWASP, CVSS) and generates downloadable PDF reports.

### SAST — Static Application Security Testing
- **Engine:** Semgrep rules (runs on WebContainer files)
- **Detects:** SQL injection, XSS, insecure crypto, hardcoded secrets, path traversal
- **Output:** Findings with CWE IDs, OWASP references, file locations, and severity
- **PDF:** Full report with executive summary, grouped by severity

### DAST — Dynamic Application Security Testing
Two scan modes available from the scan dialog:

| Mode | Engine | Time | Requirements |
|------|--------|------|-------------|
| **Quick Scan** (default) | Node.js native `fetch` | ~15 seconds | None |
| **Deep Scan** | OWASP ZAP via Docker | ~5-10 minutes | Docker Desktop |

**Quick Scan checks:**
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie security (Secure, HttpOnly, SameSite flags)
- Server information disclosure (Server, X-Powered-By headers)
- Sensitive file exposure (.env, .git/config, wp-admin, .DS_Store, server-status)
- CORS misconfiguration (wildcard origin, origin reflection, credentials with permissive origin)
- HTTPS enforcement (HTTP-to-HTTPS redirect)
- Clickjacking (frame-ancestors in CSP)

All findings include CWE IDs (e.g., CWE-1021, CWE-319, CWE-942) and OWASP Top 10 references (A01-A05:2021).

### Secrets Scan
- **Engine:** GitLeaks rule patterns
- **Detects:** API keys, tokens, passwords, private keys, cloud credentials
- **Output:** Redacted secrets with severity, file location, commit info
- **PDF:** Report with remediation guide for rotating and preventing secret leaks

### Dependency Scan (OSV)
- **Engine:** [OSV.dev](https://osv.dev) API (Google's open source vulnerability database)
- **Detects:** Known CVEs and GHSAs in npm, PyPI, Go, Rust, Maven, and other ecosystems
- **Output:** Vulnerability ID, CVSS score, affected package/version, fixed versions
- **PDF:** Report grouped by severity with upgrade recommendations

---

## Mem0 — Persistent Memory

Raphael integrates [Mem0](https://mem0.ai) for cross-session AI memory:

- **Auto-save** — Automatically extracts and stores project context, preferences, and decisions from conversations
- **Cross-session** — Memories persist across browser tabs, chat sessions, and model switches
- **Cross-model** — Switch from GPT-4 to Claude and your context follows
- **Dashboard** — View, filter, and manage memories from the Memory Viewer
- **Privacy** — All data is stored in your Mem0 account, encrypted at rest

### Setup
1. Go to **Settings > Memory**
2. Enter your Mem0 API key (get one at [app.mem0.ai](https://app.mem0.ai))
3. Toggle "Enable Memory" on
4. Start chatting — memories are saved automatically

---

## Getting Started

### Prerequisites
- **Node.js** >= 18.18.0
- **pnpm** (recommended) or npm

### Installation

```bash
# Clone the repository
git clone https://github.com/Sachin-pro-dev/Raphael-bolt.diy.git
cd Raphael-bolt.diy

# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your API keys
```

### Development

```bash
# Start the dev server
pnpm dev

# Open http://localhost:5173
```

### Other Commands

```bash
# Type checking
pnpm typecheck

# Lint and format
pnpm lint:fix

# Run tests
pnpm test

# Production build
pnpm build

# Preview production build
pnpm preview
```

### Docker

```bash
# Build development image
pnpm dockerbuild

# Build production image
pnpm dockerbuild:prod

# Run container
pnpm dockerrun
```

### Electron (Desktop App)

```bash
# Development
pnpm electron:dev

# Build for your platform
pnpm electron:build:win    # Windows
pnpm electron:build:mac    # macOS
pnpm electron:build:linux  # Linux
```

---

## Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Go to [vercel.com](https://vercel.com) and import the repository
3. Configure:
   - **Framework Preset:** Remix
   - **Build Command:** `pnpm build`
   - **Output Directory:** `build`
   - **Install Command:** `pnpm install`
4. Add environment variables (API keys from `.env.local`)
5. Deploy

Every push to `main` triggers automatic redeployment.

### Cloudflare Pages

```bash
pnpm deploy
```

---

## Architecture

```
app/
├── components/
│   ├── chat/          # Chat UI, message handling, AI interaction
│   ├── editor/        # CodeMirror editor with multi-language support
│   ├── memory/        # MemoryIndicator, MemoryViewer, SaveContextButton
│   ├── settings/      # Provider config, memory settings, connections
│   ├── ui/            # Shared UI primitives (Dialog, IconButton, Slider)
│   └── workbench/     # File explorer, preview, terminal, security dialogs
├── lib/
│   ├── common/        # System prompts for build/discuss modes
│   ├── hooks/         # React hooks (useSettings, useMessageParser)
│   ├── persistence/   # Chat history (IndexedDB)
│   ├── runtime/       # WebContainer action runner, shell commands
│   ├── services/      # Memory extractor, MCP client
│   ├── stores/        # Nanostores (chat, workbench, memory, streaming)
│   └── pdf-generator.ts  # PDF report generators for all 4 scanners
├── routes/
│   ├── api.chat.ts         # Main AI chat endpoint
│   ├── api.dast-scan.ts    # Quick DAST scanner (Node.js native)
│   ├── api.zap-scan.ts     # Deep DAST scanner (OWASP ZAP/Docker)
│   ├── api.semgrep-scan.ts # SAST scanner
│   ├── api.gitleaks-scan.ts # Secrets scanner
│   ├── api.osv-scan.ts     # Dependency vulnerability scanner
│   ├── api.memory.ts       # Mem0 CRUD operations
│   ├── api.memory-context.ts # Memory context retrieval for prompts
│   ├── api.*-pdf.ts        # PDF report generators (SAST, DAST, Secrets, OSV)
│   └── api.vercel-*.ts     # Vercel deployment endpoints
├── types/             # TypeScript interfaces (memory, OSV, actions)
└── utils/             # Helpers (constants, debounce, logger, sampler)
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | [Remix](https://remix.run) + [React 18](https://react.dev) |
| Runtime | [WebContainer](https://webcontainers.io) (in-browser Node.js) |
| Styling | [Tailwind CSS](https://tailwindcss.com) + [UnoCSS](https://unocss.dev) |
| Editor | [CodeMirror 6](https://codemirror.net) |
| Terminal | [xterm.js](https://xtermjs.org) |
| State | [Nanostores](https://github.com/nanostores/nanostores) |
| AI SDK | [Vercel AI SDK](https://sdk.vercel.ai) |
| Memory | [Mem0](https://mem0.ai) |
| UI Components | [Radix UI](https://radix-ui.com) + [Headless UI](https://headlessui.com) |
| Animation | [Framer Motion](https://www.framer.com/motion) |
| PDF | [PDFKit](https://pdfkit.org) |
| Desktop | [Electron](https://www.electronjs.org) |

---

## Environment Variables

Create a `.env.local` file in the root directory:

```env
# Required: At least one AI provider key
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_GENERATIVE_AI_API_KEY=...

# Optional: Additional providers
GROQ_API_KEY=...
OPEN_ROUTER_API_KEY=...
DEEPSEEK_API_KEY=...
MISTRAL_API_KEY=...

# Optional: Deployment
VERCEL_TOKEN=...
NETLIFY_AUTH_TOKEN=...

# Optional: GitHub integration
GITHUB_TOKEN=ghp_...
```

Mem0 API key is configured in the browser settings UI, not via environment variables.

---

## License

MIT

---

<p align="center">
  Built by the Raphael team
</p>
