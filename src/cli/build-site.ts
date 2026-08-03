import { resolve } from "node:path";

import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import { buildSite } from "../site/build-site.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

export async function ensureV5ReportIndex(root: string) {
  const path = resolve(root, "reports", "index.json");
  return parseReportIndexV5(await readJsonFile(path));
}

async function main() {
  const root = process.cwd();
  const output = resolve(process.argv[2] ?? ".site");
  await ensureV5ReportIndex(root);
  const built = await buildSite({ root, output });
  return { status: "built", files: built.files.length };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
