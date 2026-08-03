import { resolve } from "node:path";

import { parseReportIndex } from "../contracts/reports.js";
import { buildSite } from "../site/build-site.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

export async function ensureV4ReportIndex(root: string) {
  const path = resolve(root, "reports", "index.json");
  return parseReportIndex(await readJsonFile(path));
}

async function main() {
  const root = process.cwd();
  const output = resolve(process.argv[2] ?? ".site");
  await ensureV4ReportIndex(root);
  const built = await buildSite({ root, output });
  return { status: "built", files: built.files.length };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
