import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { analyzeExecutionScopes } from "../src/triage/execution-scope.js";
import type { InventoryFile } from "../src/inventory/inventory-handler.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-scope-"));
  roots.push(root);
  const inventory: InventoryFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const destination = join(root, ...path.split("/"));
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, content);
    inventory.push({
      path,
      bytes: Buffer.byteLength(content),
      sha256: createHash("sha256").update(content).digest("hex"),
      kind: "text",
    });
  }
  return { root, inventory };
}

describe("execution scope analysis", () => {
  test("classifies package, lifecycle, automation, inert, and unresolved paths", async () => {
    const input = await fixture({
      "package.json": JSON.stringify({
        exports: "./src/index.js",
        scripts: { postinstall: "node scripts/postinstall.mjs" },
      }),
      "src/index.js": ['import "../lib/runtime.js";'].join("\n"),
      "lib/runtime.js": "export const runtime = true;\n",
      "scripts/postinstall.mjs": 'import "../lib/install-helper.js";\n',
      "lib/install-helper.js": "export const installed = true;\n",
      ".github/workflows/release.yml": [
        "jobs:",
        "  release:",
        "    steps:",
        "      - run: node scripts/release.mjs",
      ].join("\n"),
      "scripts/release.mjs": 'import "../lib/release-helper.js";\n',
      "lib/release-helper.js": "export const released = true;\n",
      "scripts/local-check.mjs": "export const local = true;\n",
      "tests/fixture.js": "export const fixture = true;\n",
      "src/computed-loader.js": "export const unresolved = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(Object.fromEntries(scopes)).toMatchObject({
      "src/index.js": "runtime",
      "lib/runtime.js": "runtime",
      "scripts/postinstall.mjs": "install-update",
      "lib/install-helper.js": "install-update",
      ".github/workflows/release.yml": "automation",
      "scripts/release.mjs": "automation",
      "lib/release-helper.js": "automation",
      "scripts/local-check.mjs": "tooling-only",
      "tests/fixture.js": "test-documentation-data",
      "src/computed-loader.js": "unknown",
    });
  });

  test("follows workflow package scripts and local action entrypoints", async () => {
    const input = await fixture({
      "package.json": JSON.stringify({
        scripts: { release: "node scripts/release.mjs" },
      }),
      ".github/workflows/release.yml": [
        "jobs:",
        "  release:",
        "    steps:",
        "      - run: npm run release",
        "      - uses: ./actions/publish",
      ].join("\n"),
      "scripts/release.mjs": "export const released = true;\n",
      "actions/publish/action.yml": [
        "runs:",
        "  using: node20",
        "  main: index.js",
      ].join("\n"),
      "actions/publish/index.js": "export const published = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(Object.fromEntries(scopes)).toMatchObject({
      "scripts/release.mjs": "automation",
      "actions/publish/action.yml": "automation",
      "actions/publish/index.js": "automation",
    });
  });

  test("does not call unreferenced tooling inert when reachable code imports dynamically", async () => {
    const input = await fixture({
      "package.json": JSON.stringify({ exports: "./src/index.js" }),
      "src/index.js": "import(configuredModule);\n",
      "scripts/possibly-loaded.mjs": "export const value = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(scopes.get("scripts/possibly-loaded.mjs")).toBe("unknown");
  });

  test("does not mistake prose comments for computed module loads", async () => {
    const input = await fixture({
      "manifest.json": JSON.stringify({ js: "index.js" }),
      "index.js": [
        "// State import (validated) is documented below.",
        'import "./runtime.js";',
      ].join("\n"),
      "runtime.js": "export const runtime = true;\n",
      "scripts/local-check.mjs": "export const local = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(scopes.get("scripts/local-check.mjs")).toBe("tooling-only");
  });

  test("follows lifecycle hooks through package script aliases", async () => {
    const input = await fixture({
      "package.json": JSON.stringify({
        scripts: {
          postinstall: "npm run setup",
          setup: "node scripts/setup.mjs",
        },
      }),
      "scripts/setup.mjs": "export const installed = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(scopes.get("scripts/setup.mjs")).toBe("install-update");
  });

  test("follows a SillyTavern manifest JavaScript entrypoint", async () => {
    const input = await fixture({
      "manifest.json": JSON.stringify({
        display_name: "Runtime fixture",
        js: "src/extension/index.js",
      }),
      "src/extension/index.js": 'import "../runtime.mjs";\n',
      "src/runtime.mjs": ["import {", "  cards,", '} from "./cards.mjs";'].join(
        "\n",
      ),
      "src/cards.mjs": "export const cards = true;\n",
      "tools/unreferenced.mjs": "export const tool = true;\n",
    });

    const scopes = await analyzeExecutionScopes({
      root: input.root,
      files: input.inventory,
      limits: {
        maxFiles: 10_000,
        maxTotalBytes: 67_108_864,
        maxFileBytes: 2_097_152,
      },
    });

    expect(Object.fromEntries(scopes)).toMatchObject({
      "src/extension/index.js": "runtime",
      "src/runtime.mjs": "runtime",
      "src/cards.mjs": "runtime",
      "tools/unreferenced.mjs": "tooling-only",
    });
  });
});
