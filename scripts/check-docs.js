/**
 * Doc consistency check: every relative markdown link in the repo's docs must
 * resolve to a tracked file (guards against silent doc loss, like the
 * glossary that vanished inside an unrelated "update skills" commit).
 *
 * Usage: node scripts/check-docs.js
 */
const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set(['.opencode', '.git', 'node_modules', 'bin', 'obj', 'dist', '.vs']);
const MD_RE = /\[[^\]]*\]\(([^()\s]+(?:\s+[^()\s]+)*)\)/g;
const failures = [];

function* markdownFiles(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* markdownFiles(path.join(dir, entry.name));
    } else if (entry.name.endsWith('.md')) {
      yield path.join(dir, entry.name);
    }
  }
}

for (const file of markdownFiles('.')) {
  const text = fs.readFileSync(file, 'utf8');
  for (const match of text.matchAll(MD_RE)) {
    const target = match[1].trim();
    if (/^https?:\/\//.test(target)) continue;
    const resolved = path.resolve(path.dirname(file), target);
    if (!fs.existsSync(resolved)) {
      failures.push(`${file}: broken link (${target}) -> ${resolved}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL: ${failures.length} broken markdown link(s):`);
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('check-docs: all relative markdown links resolve.');
