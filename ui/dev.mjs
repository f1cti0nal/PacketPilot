// Dev-server launcher that pins the working directory to this folder before starting Vite,
// so Tailwind (which discovers tailwind.config.js + resolves `content` globs via process.cwd())
// works even when the launcher is invoked from a different cwd (e.g. the preview tool).
import { createServer } from "vite";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
process.chdir(root);

const server = await createServer({
  root,
  server: { port: 5180, strictPort: true, host: true },
});
await server.listen();
server.printUrls();
