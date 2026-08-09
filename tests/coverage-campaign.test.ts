import { describe, expect, test } from "vitest";

import { selectCoverageCampaign } from "../src/coverage/select-campaign.js";
import type { TargetManifestV3 } from "../src/contracts/targets.js";

const now = "2026-08-09T18:00:00.000Z";

function manifestWithDescendingPopularity(count: number): TargetManifestV3 {
  return {
    schema_version: 3,
    generated_at: now,
    repositories: Array.from({ length: count }, (_, index) => {
      const repositoryId = index + 1;
      const popularityRank = count - index;
      return {
        source_id: `github-${repositoryId}`,
        provider: "github" as const,
        repository_id: repositoryId,
        repository: `owner/repo-${repositoryId}`,
        target_sha: repositoryId.toString(16).padStart(40, "0"),
        canonical_url: `https://github.com/owner/repo-${repositoryId}`,
        project_kinds: ["extension"] as const,
        catalog_priority: {
          top_30: popularityRank <= 30,
          first_cataloged_at: "2026-07-01T00:00:00.000Z",
          popularity_rank: popularityRank,
        },
      };
    }),
  };
}

describe("one-time coverage campaign selection", () => {
  test("selects popularity ranks one through twenty instead of manifest order", async () => {
    const campaign = await selectCoverageCampaign({
      manifest: manifestWithDescendingPopularity(21),
      githubToken: "workflow-token",
      fetcher: async () => new Response(null, { status: 404 }),
      now: () => now,
    });

    expect(campaign).toMatchObject({
      popular_repository_ids: [
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
      ],
      latest_release_repository_ids: [],
      repository_ids: [
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
      ],
      remaining_repository_ids: [
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
      ],
      created_at: now,
      status: "active",
    });
  });

  test("queries every manifest repository at the fixed latest-release endpoint", async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];

    await selectCoverageCampaign({
      manifest: manifestWithDescendingPopularity(21),
      githubToken: "workflow-token",
      fetcher: async (input, init) => {
        calls.push({ url: String(input), init });
        return new Response(null, { status: 404 });
      },
      now: () => now,
    });

    expect(calls).toHaveLength(21);
    expect(new Set(calls.map(({ url }) => url)).size).toBe(21);
    expect(calls.map(({ url }) => url)).toContain(
      "https://api.github.com/repos/owner/repo-1/releases/latest",
    );
    expect(calls.map(({ url }) => url)).toContain(
      "https://api.github.com/repos/owner/repo-21/releases/latest",
    );
    expect(calls[0]!.init).toMatchObject({
      redirect: "error",
      headers: {
        accept: "application/vnd.github+json",
        authorization: "Bearer workflow-token",
        "x-github-api-version": "2022-11-28",
      },
    });
  });

  test("ranks releases by created time and repository ID at the cutoff", async () => {
    const campaign = await selectCoverageCampaign({
      manifest: manifestWithDescendingPopularity(21),
      githubToken: "workflow-token",
      fetcher: async (input) => {
        const repositoryId = Number(
          /repo-(\d+)\/releases/u.exec(String(input))![1],
        );
        const createdAt =
          repositoryId <= 2
            ? "2026-07-01T00:00:00.000Z"
            : `2026-07-${repositoryId.toString().padStart(2, "0")}T00:00:00.000Z`;
        return new Response(
          JSON.stringify({
            created_at: createdAt,
            draft: false,
            prerelease: false,
            body: "UNTRUSTED RELEASE BODY MUST NOT BE RETAINED",
            assets: [{ url: "https://attacker.example/asset" }],
          }),
          { status: 200 },
        );
      },
      now: () => now,
    });

    expect(campaign.latest_release_repository_ids).toEqual([
      1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    ]);
    expect(campaign.repository_ids).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    ]);
    expect(JSON.stringify(campaign)).not.toContain("UNTRUSTED RELEASE BODY");
    expect(JSON.stringify(campaign)).not.toContain("attacker.example");
  });

  test("fails the whole selection when latest-release returns a draft", async () => {
    await expect(
      selectCoverageCampaign({
        manifest: manifestWithDescendingPopularity(20),
        githubToken: "workflow-token",
        fetcher: async () =>
          new Response(
            JSON.stringify({
              created_at: "2026-08-01T00:00:00.000Z",
              draft: true,
              prerelease: false,
            }),
            { status: 200 },
          ),
        now: () => now,
      }),
    ).rejects.toThrow();
  });

  test("fails the whole selection when latest-release returns a prerelease", async () => {
    await expect(
      selectCoverageCampaign({
        manifest: manifestWithDescendingPopularity(20),
        githubToken: "workflow-token",
        fetcher: async () =>
          new Response(
            JSON.stringify({
              created_at: "2026-08-01T00:00:00.000Z",
              draft: false,
              prerelease: true,
            }),
            { status: 200 },
          ),
        now: () => now,
      }),
    ).rejects.toThrow();
  });

  test("fails closed on malformed release creation time", async () => {
    await expect(
      selectCoverageCampaign({
        manifest: manifestWithDescendingPopularity(20),
        githubToken: "workflow-token",
        fetcher: async () =>
          new Response(
            JSON.stringify({
              created_at: "not-a-time",
              draft: false,
              prerelease: false,
            }),
            { status: 200 },
          ),
        now: () => now,
      }),
    ).rejects.toThrow();
  });

  test("aborts on auth, rate-limit, server, and transport failures", async () => {
    const validRelease = JSON.stringify({
      created_at: "2026-08-01T00:00:00.000Z",
      draft: false,
      prerelease: false,
    });
    const failures: Array<() => Promise<Response>> = [
      async () => new Response(validRelease, { status: 401 }),
      async () => new Response(validRelease, { status: 403 }),
      async () => new Response(validRelease, { status: 429 }),
      async () => new Response(validRelease, { status: 500 }),
      async () => {
        throw new Error("simulated transport failure");
      },
    ];

    for (const fetcher of failures)
      await expect(
        selectCoverageCampaign({
          manifest: manifestWithDescendingPopularity(20),
          githubToken: "workflow-token",
          fetcher,
          now: () => now,
        }),
      ).rejects.toThrow();
  });

  test("uses the fixed eight-request concurrency ceiling", async () => {
    let active = 0;
    let peak = 0;

    await selectCoverageCampaign({
      manifest: manifestWithDescendingPopularity(21),
      githubToken: "workflow-token",
      fetcher: async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
        active -= 1;
        return new Response(null, { status: 404 });
      },
      now: () => now,
    });

    expect(peak).toBe(8);
  });

  test("rejects declared and actual release responses above the size ceiling", async () => {
    const fields = {
      created_at: "2026-08-01T00:00:00.000Z",
      draft: false,
      prerelease: false,
    };
    const oversized = [
      () =>
        new Response(JSON.stringify(fields), {
          status: 200,
          headers: { "content-length": "1000001" },
        }),
      () =>
        new Response(
          JSON.stringify({ ...fields, ignored: "x".repeat(1_000_000) }),
          { status: 200 },
        ),
    ];

    for (const response of oversized)
      await expect(
        selectCoverageCampaign({
          manifest: manifestWithDescendingPopularity(20),
          githubToken: "workflow-token",
          fetcher: async () => response(),
          now: () => now,
        }),
      ).rejects.toThrow(/size ceiling/iu);
  });

  test("requires a V3 manifest with validated repository identity", async () => {
    const wrongVersion = {
      ...manifestWithDescendingPopularity(20),
      schema_version: 2,
    };
    const wrongIdentity = manifestWithDescendingPopularity(20);
    wrongIdentity.repositories[0] = {
      ...wrongIdentity.repositories[0]!,
      source_id: "github-999",
    };

    for (const manifest of [wrongVersion, wrongIdentity])
      await expect(
        selectCoverageCampaign({
          manifest,
          githubToken: "workflow-token",
          fetcher: async () => new Response(null, { status: 404 }),
          now: () => now,
        }),
      ).rejects.toThrow();
  });
});
