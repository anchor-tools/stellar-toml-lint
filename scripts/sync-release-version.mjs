#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? '')) {
  throw new Error('Usage: node scripts/sync-release-version.mjs <semver>');
}

async function updateJson(path, update) {
  const document = JSON.parse(await readFile(path, 'utf8'));
  update(document);
  await writeFile(path, `${JSON.stringify(document, null, 2)}\n`);
}

await updateJson('package.json', (document) => {
  document.version = version;
});
await updateJson('package-lock.json', (document) => {
  document.version = version;
  document.packages[''].version = version;
});
await updateJson('editors/vscode/package.json', (document) => {
  document.version = version;
});
