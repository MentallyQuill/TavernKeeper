import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { renderHistoryHtml } from "../src/publish/render-history.js";
import {
  deriveReportAdvisory,
  renderReportV5Html,
} from "../src/publish/render-report.js";
import { projectReportToIndexV5 } from "../src/publish/publisher.js";
import { renderLandingHtml } from "../src/site/render-landing.js";
import { SITE_ROOT } from "../src/site/presentation.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

const assetRoot = join(import.meta.dirname, "..", "src", "site", "assets");

async function readPngDimensions(name: string) {
  const png = await readFile(join(assetRoot, name));
  expect(
    png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])),
  ).toBe(true);
  return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) };
}

describe("favicon assets", () => {
  test("uses the TavernKeeper orange scan mark on a transparent canvas", async () => {
    const svg = await readFile(join(assetRoot, "favicon.svg"), "utf8");

    expect(svg).toContain('viewBox="0 0 24 24"');
    expect(svg).toContain('fill="#E18A24"');
    expect(svg).toContain('fill="none"');
    expect(svg).not.toContain("#0D1117");
  });

  test("uses site-root favicon URLs in every HTML renderer", async () => {
    const report = await fixtureReportV5();
    const entry = projectReportToIndexV5(report);
    const index = {
      schema_version: 5 as const,
      generated_at: "2026-08-03T12:00:00.000Z",
      reports: [entry],
    };
    const advisories = new Map([
      [entry.report_id, deriveReportAdvisory(report)],
    ]);
    const html = [
      renderLandingHtml(index, advisories),
      renderReportV5Html(report),
      renderHistoryHtml([entry]),
    ];
    const expectedPaths = [
      "favicon.svg",
      "favicon.ico",
      "favicon-32.png",
      "favicon-16.png",
      "apple-touch-icon.png",
      "favicon-192.png",
      "favicon-512.png",
    ];

    for (const page of html) {
      for (const path of expectedPaths)
        expect(page).toContain(`href="${SITE_ROOT}assets/${path}"`);
      expect(page).not.toContain('href="./assets/');
    }
  });

  test("contains square PNG derivatives and a three-entry ICO", async () => {
    const expectedDimensions = {
      "favicon-16.png": 16,
      "favicon-32.png": 32,
      "favicon-48.png": 48,
      "apple-touch-icon.png": 180,
      "favicon-192.png": 192,
      "favicon-512.png": 512,
    };

    for (const [name, size] of Object.entries(expectedDimensions))
      expect(await readPngDimensions(name)).toEqual({
        width: size,
        height: size,
      });

    const ico = await readFile(join(assetRoot, "favicon.ico"));
    expect(ico.readUInt16LE(0)).toBe(0);
    expect(ico.readUInt16LE(2)).toBe(1);
    expect(ico.readUInt16LE(4)).toBe(3);
  });
});
