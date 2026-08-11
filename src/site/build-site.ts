import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import { renderHistoryHtml } from "../publish/render-history.js";
import {
  deriveReportAdvisory,
  renderReportV5Html,
} from "../publish/render-report.js";
import { reportPath } from "../publish/report-path.js";
import { sanitizeReportV5 } from "../publish/sanitize.js";
import { renderLandingHtml } from "./render-landing.js";
import { REPORT_SEARCH_SCRIPT } from "./search-script.js";

export interface BuildSiteInput {
  root: string;
  output: string;
}

function inside(path: string, parent: string) {
  return path === parent || path.startsWith(`${parent}${sep}`);
}

function validateOutput(root: string, output: string, sources: string[]) {
  if (!inside(output, root) || output === root)
    throw new Error(
      "Site output path must be a dedicated directory inside the repository.",
    );
  if (
    sources.some((source) => inside(output, source) || inside(source, output))
  )
    throw new Error(
      "Site output path must not overlap an allowlisted source tree.",
    );
}

async function copyTree(source: string, destination: string) {
  let entries;
  try {
    entries = await readdir(source, { withFileTypes: true });
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    )
      return;
    throw error;
  }
  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const sourcePath = join(source, entry.name);
    const destinationPath = join(destination, entry.name);
    if (entry.isSymbolicLink())
      throw new Error(
        `Pages source must not contain symbolic links: ${sourcePath}`,
      );
    if (entry.isDirectory()) {
      await copyTree(sourcePath, destinationPath);
      continue;
    }
    if (!entry.isFile())
      throw new Error(`Pages source contains a non-file entry: ${sourcePath}`);
    await mkdir(dirname(destinationPath), { recursive: true });
    await copyFile(sourcePath, destinationPath);
  }
}

async function listFiles(root: string, directory = root): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await listFiles(root, path)));
    else if (entry.isFile())
      files.push(relative(root, path).replaceAll("\\", "/"));
    else throw new Error(`Pages output contains a non-file entry: ${path}`);
  }
  return files.sort((left, right) => left.localeCompare(right));
}

function publicDirectory(urlInput: string) {
  const url = new URL(urlInput);
  const prefix = "/TavernKeeper/";
  if (
    url.origin !== "https://mentallyquill.github.io" ||
    !url.pathname.startsWith(prefix)
  )
    throw new Error("Public report URL is outside the TavernKeeper site.");
  const segments = url.pathname.slice(prefix.length).split("/").filter(Boolean);
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        segment === "." ||
        segment === ".." ||
        decodeURIComponent(segment).includes("\\"),
    )
  )
    throw new Error("Public report URL has an unsafe path.");
  return segments.map(decodeURIComponent).join("/");
}

async function readJson(path: string) {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

export async function buildSite({
  root: rootInput,
  output: outputInput,
}: BuildSiteInput) {
  const root = resolve(rootInput);
  const output = resolve(outputInput);
  const sources = [
    join(root, "reports"),
    join(root, "schemas"),
    join(root, "docs", "rules"),
    join(root, "src", "site", "assets"),
  ];
  validateOutput(root, output, sources);
  const index = parseReportIndexV5(
    await readJson(join(root, "reports", "index.json")),
  );
  const preferredReports = await Promise.all(
    index.reports.map(async (entry) => {
      const directory = publicDirectory(entry.report_url);
      const report = sanitizeReportV5(
        await readJson(join(root, ...directory.split("/"), "report.json")),
      );
      if (reportPath(report) !== directory)
        throw new Error(
          "Report identity does not match its indexed directory.",
        );
      return {
        directory,
        entry,
        report,
      };
    }),
  );
  const advisories = new Map(
    preferredReports.map(({ entry, report }) => [
      entry.report_id,
      deriveReportAdvisory(report),
    ]),
  );

  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  await copyTree(sources[0]!, join(output, "reports"));
  await copyTree(sources[1]!, join(output, "schemas"));
  await copyTree(sources[2]!, join(output, "rules"));
  await writeFile(
    join(output, "reports", "index.json"),
    `${JSON.stringify(index, null, 2)}\n`,
  );
  await mkdir(join(output, "assets"), { recursive: true });
  await copyTree(sources[3]!, join(output, "assets"));
  await writeFile(
    join(output, "index.html"),
    renderLandingHtml(index, advisories),
  );
  await writeFile(
    join(output, "assets", "report-search.js"),
    REPORT_SEARCH_SCRIPT,
  );

  for (const { directory, report } of preferredReports) {
    await writeFile(
      join(output, ...directory.split("/"), "index.html"),
      renderReportV5Html(report),
    );
  }

  const histories = new Set(index.reports.map((entry) => entry.history_url));
  for (const historyUrl of histories) {
    const directory = publicDirectory(historyUrl);
    const history = await readJson(
      join(root, ...directory.split("/"), "history.json"),
    );
    if (!Array.isArray(history))
      throw new Error("Public report history must be an array.");
    await writeFile(
      join(output, ...directory.split("/"), "index.html"),
      renderHistoryHtml(history),
    );
  }
  await writeFile(join(output, ".nojekyll"), "");

  return { output, files: await listFiles(output) };
}
