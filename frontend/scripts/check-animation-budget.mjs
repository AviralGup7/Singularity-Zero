import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

const DIST_ASSETS = join(process.cwd(), 'dist', 'assets');

const BUDGETS = {
  totalJsGzip: 1050 * 1024,
  appShellChunkGzip: 95 * 1024,
  gsapChunkGzip: 40 * 1024,
  lottieChunkGzip: 75 * 1024,
};

function formatBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

function gzipSizeOf(filePath) {
  const source = readFileSync(filePath);
  return gzipSync(source, { level: 9 }).length;
}

function getJsAssets() {
  const entries = readdirSync(DIST_ASSETS);
  return entries
    .filter((name) => name.endsWith('.js'))
    .map((name) => {
      const path = join(DIST_ASSETS, name);
      const stat = statSync(path);
      return {
        name,
        path,
        rawSize: stat.size,
        gzipSize: gzipSizeOf(path),
      };
    });
}

const jsAssets = getJsAssets();
const totalJsGzip = jsAssets.reduce((sum, item) => sum + item.gzipSize, 0);
const appShellChunk = jsAssets.find((item) => /^index-.*\.js$/i.test(item.name));
const gsapChunk = jsAssets.find((item) => /^gsap-.*\.js$/i.test(item.name));
const lottieChunk = jsAssets.find((item) => /lottie/i.test(item.name));

const failures = [];

if (totalJsGzip > BUDGETS.totalJsGzip) {
  failures.push(
    `Total JS gzip size ${formatBytes(totalJsGzip)} exceeds budget ${formatBytes(BUDGETS.totalJsGzip)}.`
  );
}
if (appShellChunk && appShellChunk.gzipSize > BUDGETS.appShellChunkGzip) {
  failures.push(
    `App shell chunk ${appShellChunk.name} gzip size ${formatBytes(appShellChunk.gzipSize)} exceeds budget ${formatBytes(BUDGETS.appShellChunkGzip)}.`
  );
}
if (gsapChunk && gsapChunk.gzipSize > BUDGETS.gsapChunkGzip) {
  failures.push(
    `GSAP chunk ${gsapChunk.name} gzip size ${formatBytes(gsapChunk.gzipSize)} exceeds budget ${formatBytes(BUDGETS.gsapChunkGzip)}.`
  );
}
if (lottieChunk && lottieChunk.gzipSize > BUDGETS.lottieChunkGzip) {
  failures.push(
    `Lottie chunk ${lottieChunk.name} gzip size ${formatBytes(lottieChunk.gzipSize)} exceeds budget ${formatBytes(BUDGETS.lottieChunkGzip)}.`
  );
}

console.log('Animation Budget Report');
console.log(`- Total JS (gzip): ${formatBytes(totalJsGzip)}`);
if (appShellChunk) console.log(`- App shell: ${appShellChunk.name} (${formatBytes(appShellChunk.gzipSize)})`);
if (gsapChunk) console.log(`- GSAP chunk: ${gsapChunk.name} (${formatBytes(gsapChunk.gzipSize)})`);
if (lottieChunk) console.log(`- Lottie chunk: ${lottieChunk.name} (${formatBytes(lottieChunk.gzipSize)})`);

if (failures.length > 0) {
  console.error('\nAnimation budget check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Animation budget check passed.');
