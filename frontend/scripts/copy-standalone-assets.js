/**
 * RootMesh Frontend — Standalone Distribution Asset Packaging
 * Automatically synchronizes public/ and .next/static/ into .next/standalone
 * to ensure self-contained, reproducible production deployments.
 */
const fs = require('fs');
const path = require('path');

const frontendRoot = path.resolve(__dirname, '..');
const standaloneDir = path.join(frontendRoot, '.next', 'standalone');

if (!fs.existsSync(standaloneDir)) {
  console.log('[copy-standalone-assets] Standalone directory not found (skipping).');
  process.exit(0);
}

// 1. Copy public/ -> .next/standalone/public/
const publicSrc = path.join(frontendRoot, 'public');
const publicDest = path.join(standaloneDir, 'public');
if (fs.existsSync(publicSrc)) {
  fs.cpSync(publicSrc, publicDest, { recursive: true, force: true });
  console.log('[copy-standalone-assets] Synced public/ -> .next/standalone/public/');
}

// 2. Copy .next/static/ -> .next/standalone/.next/static/
const staticSrc = path.join(frontendRoot, '.next', 'static');
const staticDest = path.join(standaloneDir, '.next', 'static');
if (fs.existsSync(staticSrc)) {
  fs.mkdirSync(path.dirname(staticDest), { recursive: true });
  fs.cpSync(staticSrc, staticDest, { recursive: true, force: true });
  console.log('[copy-standalone-assets] Synced .next/static/ -> .next/standalone/.next/static/');
}

console.log('[copy-standalone-assets] Packaging verification:');
const checkWordmark = path.join(standaloneDir, 'public', 'brand', 'rootmesh-wordmark.png');
const checkIcon = path.join(standaloneDir, 'public', 'brand', 'rootmesh-icon.png');
console.log(' - Wordmark exists in standalone:', fs.existsSync(checkWordmark));
console.log(' - Icon exists in standalone:', fs.existsSync(checkIcon));
