/**
 * Pre-commit secret scanner.
 *
 * Uses `gitleaks protect --staged` when the `gitleaks` CLI is installed on PATH;
 * otherwise falls back to a built-in pattern scanner over staged additions
 * and forbidden credential file paths.
 *
 * Usage:
 *   node scripts/check-secrets.js            # scan staged changes (default)
 *   node scripts/check-secrets.js --staged   # scan staged changes
 *   node scripts/check-secrets.js --all      # scan all tracked files (built-in scanner)
 *
 * Suppress a known false positive on a line by adding:
 *   gitleaks:allow   or   pragma: allowlist secret
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ALLOW_INLINE_RE = /\b(?:gitleaks:allow|pragma:\s*allowlist\s*secret|no-secret)\b/i;

const FORBIDDEN_FILE_PATTERNS = [
  {
    id: 'env-file',
    description: 'Environment file (.env) must not be committed',
    test: (filePath) => {
      const base = path.basename(filePath);
      if (/^\.env\.(?:example|sample|template|defaults|schema)$/i.test(base)) return false;
      return /^\.env(?:\..+)?$/i.test(base);
    },
  },
  {
    id: 'private-key-file',
    description: 'Private key / certificate store file must not be committed',
    test: (filePath) => /\.(?:pem|key|pfx|p12|jks|keystore)$/i.test(filePath) || /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/i.test(filePath),
  },
];

const SECRET_RULES = [
  {
    id: 'private-key',
    description: 'Private key block header',
    regex: /-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY-----/,
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS Access Key ID',
    regex: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/,
    isPlaceholder: (match) => /EXAMPLE$/i.test(match[0]),
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS Secret Access Key assignment',
    regex: /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    isPlaceholder: (match) => /EXAMPLE/i.test(match[1]),
  },
  {
    id: 'github-token',
    description: 'GitHub Personal Access / OAuth / App Token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,255}\b/,
  },
  {
    id: 'gitlab-pat',
    description: 'GitLab Personal Access Token',
    regex: /\bglpat-[A-Za-z0-9\-=_]{20,}\b/,
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI API Key',
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API Key',
    regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'google-api-key',
    description: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/,
  },
  {
    id: 'slack-token',
    description: 'Slack Token',
    regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b/,
  },
  {
    id: 'slack-webhook',
    description: 'Slack Incoming Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,}/,
  },
  {
    id: 'stripe-live-key',
    description: 'Stripe Live API Key',
    regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/,
  },
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
  },
  {
    id: 'npm-access-token',
    description: 'npm Access Token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
  },
  {
    id: 'azure-storage-connection-string',
    description: 'Azure Storage AccountKey in connection string',
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;\s"']+;AccountKey=([A-Za-z0-9+/=]{40,})/i,
  },
  {
    id: 'connection-string-credentials',
    description: 'Database connection URI with embedded password',
    regex: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqp|amqps):\/\/([^:\s/"'@]+):([^@\s/"']+)@/i,
    isPlaceholder: (match) => isPlaceholderValue(match[2]),
  },
  {
    id: 'ado-connection-password',
    description: 'ADO.NET connection string with embedded password',
    regex: /;\s*(?:Password|Pwd)\s*=\s*([^;"'\s\r\n]{8,})/i,
    isPlaceholder: (match) => isPlaceholderValue(match[1]),
  },
  {
    id: 'jwt-token',
    description: 'Hardcoded JSON Web Token (JWT)',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}\b/,
  },
  {
    id: 'generic-secret-assignment',
    description: 'Hardcoded secret / token / API key assignment',
    regex: /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["']([A-Za-z0-9/+_\-=]{16,})["']/i,
    isPlaceholder: (match) => isPlaceholderValue(match[1]),
  },
];

const PLACEHOLDER_RE = /^(?:admin|password|passwd|secret|changeme|replace[_-]?me|your[_-]?.*|example.*|test.*|dummy.*|sample.*|todo.*|none|null|undefined|empty|true|false|xxx+|000+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[A-Za-z0-9_]+%)$/i;

function isPlaceholderValue(value) {
  if (!value) return true;
  const trimmed = value.trim();
  if (trimmed.length < 8) return true;
  if (PLACEHOLDER_RE.test(trimmed)) return true;
  if (/^\*+$/.test(trimmed) || /^\.+$/.test(trimmed)) return true;
  return false;
}

function redact(value) {
  const str = String(value);
  if (str.length <= 8) return '***';
  return `${str.slice(0, 4)}...${str.slice(-4)}`;
}

function resolveGitleaksBin() {
  try {
    execFileSync('gitleaks', ['version'], { stdio: 'ignore' });
    return 'gitleaks';
  } catch {
    if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
      const wingetLink = path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Links', 'gitleaks.exe');
      if (fs.existsSync(wingetLink)) return wingetLink;

      const packagesDir = path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Packages');
      if (fs.existsSync(packagesDir)) {
        const pkg = fs.readdirSync(packagesDir).find((d) => d.startsWith('Gitleaks.Gitleaks_'));
        if (pkg) {
          const candidate = path.join(packagesDir, pkg, 'gitleaks.exe');
          if (fs.existsSync(candidate)) return candidate;
        }
      }
    }
    return null;
  }
}

function runGitleaksStaged(bin) {
  try {
    execFileSync(bin, ['protect', '--staged', '--redact', '--no-banner', '--verbose'], {
      stdio: 'inherit',
    });
    return 0;
  } catch (err) {
    return typeof err.status === 'number' ? err.status : 1;
  }
}

function git(args) {
  return execFileSync('git', args, {
    encoding: 'utf8',
    maxBuffer: 50 * 1024 * 1024,
  });
}

function getStagedFiles() {
  const out = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']);
  return out.split('\0').filter(Boolean);
}

function parseStagedAdditions() {
  const diff = git(['diff', '--cached', '--unified=0', '--no-color', '--diff-filter=ACMR']);
  const lines = diff.split(/\r?\n/);
  const entries = [];

  let currentFile = null;
  let currentLine = 0;

  for (const rawLine of lines) {
    if (rawLine.startsWith('+++ ')) {
      const target = rawLine.slice(4).trim();
      if (target === '/dev/null') {
        currentFile = null;
      } else {
        currentFile = target.startsWith('b/') ? target.slice(2) : target;
      }
      continue;
    }

    if (rawLine.startsWith('@@ ')) {
      const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine);
      if (match) {
        currentLine = parseInt(match[1], 10);
      }
      continue;
    }

    if (!currentFile) continue;

    if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      entries.push({
        file: currentFile,
        line: currentLine,
        content: rawLine.slice(1),
      });
      currentLine += 1;
    }
  }

  return entries;
}

function getAllTrackedAdditions() {
  const out = git(['ls-files', '-z']);
  const files = out.split('\0').filter(Boolean);
  const entries = [];

  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) continue;

    const buffer = fs.readFileSync(file);
    if (buffer.includes(0)) continue; // skip binary files

    const text = buffer.toString('utf8');
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      entries.push({
        file,
        line: i + 1,
        content: lines[i],
      });
    }
  }

  return { files, entries };
}

function scanEntries(files, entries) {
  const findings = [];

  for (const file of files) {
    const normalized = file.replace(/\\/g, '/');
    for (const rule of FORBIDDEN_FILE_PATTERNS) {
      if (rule.test(normalized)) {
        findings.push({
          file: normalized,
          line: 0,
          ruleId: rule.id,
          description: rule.description,
          sample: path.basename(normalized),
        });
      }
    }
  }

  for (const entry of entries) {
    if (ALLOW_INLINE_RE.test(entry.content)) continue;

    for (const rule of SECRET_RULES) {
      const match = rule.regex.exec(entry.content);
      if (!match) continue;
      if (rule.isPlaceholder && rule.isPlaceholder(match)) continue;

      findings.push({
        file: entry.file,
        line: entry.line,
        ruleId: rule.id,
        description: rule.description,
        sample: redact(match[0]),
      });
    }
  }

  return findings;
}

function main() {
  const args = new Set(process.argv.slice(2));
  const scanAll = args.has('--all');
  const forceFallback = args.has('--fallback');

  const gitleaksBin = !scanAll && !forceFallback ? resolveGitleaksBin() : null;
  if (gitleaksBin) {
    console.log('check-secrets: running gitleaks protect --staged...');
    const code = runGitleaksStaged(gitleaksBin);
    if (code !== 0) {
      console.error('check-secrets: REJECTED by gitleaks — potential secret detected in staged changes.');
      process.exit(code);
    }
  }

  const files = scanAll ? getAllTrackedAdditions().files : getStagedFiles();
  if (files.length === 0) {
    console.log('check-secrets: no staged files to scan.');
    return;
  }

  const entries = scanAll ? getAllTrackedAdditions().entries : parseStagedAdditions();
  const findings = scanEntries(files, entries);

  if (findings.length > 0) {
    console.error(`\ncheck-secrets: REJECTED — ${findings.length} potential secret(s) detected:`);
    for (const f of findings) {
      const loc = f.line > 0 ? `${f.file}:${f.line}` : f.file;
      console.error(`  - [${f.ruleId}] ${loc} — ${f.description} (${f.sample})`);
    }
    console.error('\nIf a finding is an intentional test fixture or false positive, annotate the line with:');
    console.error('  // gitleaks:allow   (or # gitleaks:allow)');
    process.exit(1);
  }

  const mode = scanAll ? 'all tracked files' : `${files.length} staged file(s)`;
  const engine = gitleaksBin ? 'gitleaks + built-in rules' : 'built-in scanner';
  console.log(`check-secrets: no secrets detected (${mode}, ${engine}).`);
}

if (require.main === module) {
  main();
}

module.exports = {
  FORBIDDEN_FILE_PATTERNS,
  SECRET_RULES,
  scanEntries,
};
