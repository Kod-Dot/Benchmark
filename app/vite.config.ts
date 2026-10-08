import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Browser preview only (vite dev / vite preview, never the desktop build):
// serves the files written by `cargo run -p dca-core --bin preview-data`:
// the real catalog summary and views of the EXAMPLE assessments in fixtures/,
// so the UI can be reviewed in a browser without the Tauri backend.
function previewData(): Plugin {
  const dir = resolve(__dirname, '.preview');
  const serve = (
    req: { url?: string },
    res: { setHeader(k: string, v: string): void; end(b: string): void; statusCode: number },
  ) => {
    const name = (req.url ?? '').replace(/^\//, '').split('?')[0];
    const file = resolve(dir, name);
    if (!/^[a-z0-9-]+\.json$/.test(name) || !existsSync(file)) {
      res.statusCode = 404;
      res.end('');
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(readFileSync(file, 'utf8'));
  };
  return {
    name: 'dca-preview-data',
    configureServer(server) {
      server.middlewares.use('/__preview', serve);
    },
    configurePreviewServer(server) {
      server.middlewares.use('/__preview', serve);
    },
  };
}

// Two builds into dist/: the app (index.html, also the offline dashboard)
// and, with --mode report, the printable reports (report.html). Separate
// builds keep each page to one script, which the export inlines.
export default defineConfig(({ mode }) => ({
  plugins: [svelte(), previewData()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build:
    mode === 'report'
      ? { target: 'es2022', outDir: 'dist', emptyOutDir: false, rollupOptions: { input: resolve(__dirname, 'report.html') } }
      : { target: 'es2022', outDir: 'dist', emptyOutDir: true },
}));
