import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";

import { expect, test } from "vitest";
import { parse } from "yaml";

const workflowDirectory = resolve(".github/workflows");
const appTokenAction =
  "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1";

async function workflowSources() {
  const names = (await readdir(workflowDirectory)).filter((name) =>
    /\.ya?ml$/u.test(name),
  );
  return Promise.all(
    names.map(async (name) => ({
      name,
      source: await readFile(resolve(workflowDirectory, name), "utf8"),
    })),
  );
}

function walk(value: unknown, visit: (candidate: unknown) => void) {
  visit(value);
  if (Array.isArray(value)) {
    value.forEach((child) => walk(child, visit));
    return;
  }
  if (value === null || typeof value !== "object") return;
  Object.values(value).forEach((child) => walk(child, visit));
}

test("production auth surfaces contain no installation-token format assumptions", async () => {
  const sources = await workflowSources();
  const corpus = [
    ...sources,
    {
      name: "scripts/check-workflow-policy.mjs",
      source: await readFile("scripts/check-workflow-policy.mjs", "utf8"),
    },
  ];

  for (const { name, source } of corpus) {
    expect(source, name).not.toMatch(/X-GitHub-Stateless-S2S-Token/iu);
    expect(source, name).not.toMatch(/\bghs_/u);
    expect(source, name).not.toMatch(
      /\b(?:GH_TOKEN|GITHUB_TOKEN|TOKEN)\b[^\n]{0,120}(?:\.length|\.slice\(|\.substring\()/iu,
    );
    expect(source, name).not.toMatch(
      /\b(?:GH_TOKEN|GITHUB_TOKEN|TOKEN)\b[^\n]{0,120}(?:jwt-decode|decodeJwt|atob\(|\.split\(\s*["']\.["']\s*\))/iu,
    );
  }
  expect(sources.map(({ name }) => name)).not.toEqual(
    expect.arrayContaining(["token-compat.yml", "token-compat-receiver.yml"]),
  );
});

test("wake and Publisher token outputs pass to GitHub consumers without mutation", async () => {
  const syntheticToken = `opaque.installation.${"y".repeat(640)}`;
  expect(syntheticToken.length).toBeGreaterThan(600);
  const documents = (await workflowSources()).map(({ name, source }) => ({
    name,
    value: parse(source),
  }));
  let tokenSteps = 0;
  let consumers = 0;

  for (const { name, value } of documents) {
    const references = new Set<string>();
    walk(value, (candidate) => {
      if (
        candidate !== null &&
        typeof candidate === "object" &&
        "uses" in candidate &&
        candidate.uses === appTokenAction &&
        "id" in candidate &&
        typeof candidate.id === "string"
      ) {
        references.add(`\${{ steps.${candidate.id}.outputs.token }}`);
        tokenSteps += 1;
      }
    });
    walk(value, (candidate) => {
      if (
        candidate !== null &&
        typeof candidate === "object" &&
        "GH_TOKEN" in candidate &&
        typeof candidate.GH_TOKEN === "string" &&
        references.has(candidate.GH_TOKEN)
      ) {
        const transported = new Map(
          [...references].map((reference) => [reference, syntheticToken]),
        ).get(candidate.GH_TOKEN);
        expect(transported, name).toBe(syntheticToken);
        consumers += 1;
      }
    });
  }

  expect(tokenSteps).toBeGreaterThanOrEqual(4);
  expect(consumers).toBeGreaterThanOrEqual(4);
});
