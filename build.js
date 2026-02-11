import * as esbuild from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'fs';

const isWatch = process.argv.includes('--watch');

// Clean dist folder
try {
  rmSync('dist', { recursive: true });
} catch (e) {}

mkdirSync('dist', { recursive: true });
mkdirSync('dist/popup', { recursive: true });
mkdirSync('dist/confirm', { recursive: true });
mkdirSync('dist/icons', { recursive: true });

// Copy static files
cpSync('manifest.json', 'dist/manifest.json');
cpSync('popup/popup.html', 'dist/popup/popup.html');
cpSync('popup/popup.css', 'dist/popup/popup.css');
cpSync('confirm/confirm.html', 'dist/confirm/confirm.html');
cpSync('confirm/confirm.js', 'dist/confirm/confirm.js');
cpSync('content.js', 'dist/content.js');
cpSync('injected.js', 'dist/injected.js');
cpSync('icons', 'dist/icons', { recursive: true });

// Build configuration
const buildOptions = {
  bundle: true,
  format: 'esm',
  target: 'chrome100',
  minify: !isWatch,
  sourcemap: isWatch,
};

// Build background script
const backgroundBuild = esbuild.build({
  ...buildOptions,
  entryPoints: ['background.js'],
  outfile: 'dist/background.js',
});

// Build popup script
const popupBuild = esbuild.build({
  ...buildOptions,
  entryPoints: ['popup/popup.js'],
  outfile: 'dist/popup/popup.js',
  format: 'iife',
});

await Promise.all([backgroundBuild, popupBuild]);

console.log('Build complete! Extension is in ./dist folder');

if (isWatch) {
  console.log('Watching for changes...');

  const ctx1 = await esbuild.context({
    ...buildOptions,
    entryPoints: ['background.js'],
    outfile: 'dist/background.js',
  });

  const ctx2 = await esbuild.context({
    ...buildOptions,
    entryPoints: ['popup/popup.js'],
    outfile: 'dist/popup/popup.js',
    format: 'iife',
  });

  await ctx1.watch();
  await ctx2.watch();
}
