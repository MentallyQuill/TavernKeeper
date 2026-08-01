import { resolve } from "node:path";

import { buildSite } from "../site/build-site.js";
import { isDirectExecution, runJsonCli } from "./io.js";

async function main() {
  const root = process.cwd();
  const output = resolve(process.argv[2] ?? ".site");
  const built = await buildSite({ root, output });
  return { status: "built", files: built.files.length };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
