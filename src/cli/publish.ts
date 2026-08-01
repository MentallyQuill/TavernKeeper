import { readdir } from "node:fs/promises";
import { join } from "node:path";

import { parseOperationsState } from "../operations/state.js";
import { recordFailure } from "../operations/retry.js";
import { publishCandidates } from "../publish/publisher.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";
import { ScanTransitionSchema, type ScanTransition } from "./transition.js";

async function findNamedFiles(
  root: string,
  filename: string,
): Promise<string[]> {
  const matches: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory())
      matches.push(...(await findNamedFiles(path, filename)));
    else if (entry.isFile() && entry.name === filename) matches.push(path);
  }
  return matches.sort();
}

async function main() {
  const artifactsRoot = process.argv[2] ?? "artifacts";
  const [candidatePaths, transitionPaths] = await Promise.all([
    findNamedFiles(artifactsRoot, "candidate.json"),
    findNamedFiles(artifactsRoot, "transition.json"),
  ]);
  const candidates = await Promise.all(candidatePaths.map(readJsonFile));
  const transitions = await Promise.all(
    transitionPaths.map(async (path) =>
      ScanTransitionSchema.parse(await readJsonFile(path)),
    ),
  );
  const now = new Date().toISOString();
  let state = parseOperationsState(await readJsonFile("operations/state.json"));
  for (const transition of transitions) {
    if (transition.status !== "failure") continue;
    state = recordFailure(state, {
      target: transition.target,
      code: transition.code,
      scope: transition.scope,
      at: transition.at,
    }).state;
  }
  const systemFailure = transitions.some(
    (transition) =>
      transition.status === "failure" && transition.scope === "system",
  );
  const published = await publishCandidates({
    root: process.cwd(),
    candidates: systemFailure
      ? []
      : candidates.map((value) => {
          if (
            value === null ||
            typeof value !== "object" ||
            !("report" in value)
          )
            throw new Error("Candidate artifact is invalid.");
          return value.report;
        }),
    state,
    generatedAt: now,
  });
  return {
    status: systemFailure ? "blocked" : "published",
    reports: published.published.length,
    terminal_failures: transitions
      .filter(
        (
          transition,
        ): transition is Extract<ScanTransition, { status: "failure" }> =>
          transition.status === "failure",
      )
      .filter(({ target }) =>
        published.state.retries.some(
          (retry) =>
            retry.repository_id === target.repository_id &&
            retry.target_sha === target.target_sha &&
            retry.exhausted,
        ),
      ).length,
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
