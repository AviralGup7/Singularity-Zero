import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = process.cwd();
const SRC_DIR = join(ROOT, 'src');
const forbiddenPhrase = (process.env.COPY_GUARD_FORBIDDEN || 'cyberpunk 2077').trim().toLowerCase();

const allowedExtensions = new Set(['.tsx', '.jsx', '.json']);
const skipPathParts = new Set(['node_modules', 'dist', 'coverage', '__snapshots__', 'stories', 'tests']);

function walkFiles(dir, found = []) {
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const abs = join(dir, entry);
    const rel = relative(ROOT, abs);
    const segments = rel.split(/[\\/]/g);
    if (segments.some(part => skipPathParts.has(part))) {
      continue;
    }
    const stats = statSync(abs);
    if (stats.isDirectory()) {
      walkFiles(abs, found);
      continue;
    }
    const extension = abs.slice(abs.lastIndexOf('.')).toLowerCase();
    if (!allowedExtensions.has(extension)) {
      continue;
    }
    const inI18n = rel.includes(`src${process.platform === 'win32' ? '\\' : '/'}i18n`);
    if (!inI18n && extension === '.json') {
      continue;
    }
    found.push(abs);
  }
  return found;
}

function lineNumberForOffset(content, offset) {
  const prior = content.slice(0, offset);
  return prior.split(/\r?\n/).length;
}

const files = walkFiles(SRC_DIR);
const hits = [];

for (const file of files) {
  const content = readFileSync(file, 'utf8');
  const normalized = content.toLowerCase();
  let index = normalized.indexOf(forbiddenPhrase);
  while (index !== -1) {
    hits.push({
      file: relative(ROOT, file),
      line: lineNumberForOffset(content, index),
    });
    index = normalized.indexOf(forbiddenPhrase, index + forbiddenPhrase.length);
  }
}

if (hits.length > 0) {
  console.error('Copy guard failed. Forbidden exact phrase detected in user-facing sources:');
  for (const hit of hits) {
    console.error(`- ${hit.file}:${hit.line}`);
  }
  process.exit(1);
}

console.log('Copy guard passed.');
