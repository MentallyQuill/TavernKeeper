import { z } from "zod";

import { CURRENT_SCANNER_POLICY_VERSION } from "../config/policy.js";
import { TargetManifestV3Schema } from "../contracts/targets.js";
import {
  COVERAGE_CAMPAIGN_ID,
  CoverageCampaignSchema,
} from "../operations/state.js";

export type CoverageFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

const MAXIMUM_RELEASE_RESPONSE_BYTES = 1_000_000;
const LatestReleaseSchema = z.looseObject({
  created_at: z.iso.datetime(),
  draft: z.literal(false),
  prerelease: z.literal(false),
});

function latestReleaseEndpoint(repository: string) {
  const [owner, name] = repository.split("/");
  return `https://api.github.com/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(name!)}/releases/latest`;
}

async function parseLatestRelease(
  response: Response,
  repositoryId: number,
) {
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("GitHub latest-release lookup failed.");
  const declaredBytes = Number(response.headers.get("content-length") ?? "0");
  if (
    Number.isFinite(declaredBytes) &&
    declaredBytes > MAXIMUM_RELEASE_RESPONSE_BYTES
  )
    throw new Error("GitHub latest-release response exceeded its size ceiling.");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAXIMUM_RELEASE_RESPONSE_BYTES)
    throw new Error("GitHub latest-release response exceeded its size ceiling.");
  const release = LatestReleaseSchema.parse(JSON.parse(text));
  return { repositoryId, createdAt: release.created_at };
}

export async function selectCoverageCampaign(input: {
  manifest: unknown;
  githubToken: string;
  fetcher: CoverageFetch;
  now: () => string;
}) {
  const manifest = TargetManifestV3Schema.parse(input.manifest);
  const popularRepositoryIds = manifest.repositories
    .filter(
      ({ catalog_priority }) => catalog_priority.popularity_rank <= 20,
    )
    .sort(
      (left, right) =>
        left.catalog_priority.popularity_rank -
        right.catalog_priority.popularity_rank,
    )
    .map(({ repository_id }) => repository_id)
    .sort((left, right) => left - right);
  if (popularRepositoryIds.length !== 20)
    throw new Error("The V3 manifest must publish popularity ranks 1-20.");

  const releaseResults: Array<{
    repositoryId: number;
    createdAt: string;
  } | null> = new Array(manifest.repositories.length);
  let nextRepositoryIndex = 0;
  async function worker() {
    while (nextRepositoryIndex < manifest.repositories.length) {
      const index = nextRepositoryIndex;
      nextRepositoryIndex += 1;
      const target = manifest.repositories[index]!;
      const response = await input.fetcher(
        latestReleaseEndpoint(target.repository),
        {
          redirect: "error",
          headers: {
            accept: "application/vnd.github+json",
            authorization: `Bearer ${input.githubToken}`,
            "x-github-api-version": "2022-11-28",
          },
          signal: AbortSignal.timeout(30_000),
        },
      );
      releaseResults[index] = await parseLatestRelease(
        response,
        target.repository_id,
      );
    }
  }
  const workers = await Promise.allSettled(
    Array.from(
      { length: Math.min(8, manifest.repositories.length) },
      worker,
    ),
  );
  const failure = workers.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (failure !== undefined) throw failure.reason;
  const releases = releaseResults.filter(
    (
      release,
    ): release is { repositoryId: number; createdAt: string } =>
      release !== null,
  );

  const latestReleaseRepositoryIds = releases
    .sort(
      (left, right) =>
        Date.parse(right.createdAt) - Date.parse(left.createdAt) ||
        left.repositoryId - right.repositoryId,
    )
    .slice(0, 20)
    .map(({ repositoryId }) => repositoryId)
    .sort((left, right) => left - right);
  const repositoryIds = [
    ...new Set([...popularRepositoryIds, ...latestReleaseRepositoryIds]),
  ].sort((left, right) => left - right);

  return CoverageCampaignSchema.parse({
    id: COVERAGE_CAMPAIGN_ID,
    scanner_policy_version: CURRENT_SCANNER_POLICY_VERSION,
    created_at: input.now(),
    status: "active" as const,
    popular_repository_ids: popularRepositoryIds,
    latest_release_repository_ids: latestReleaseRepositoryIds,
    repository_ids: repositoryIds,
    remaining_repository_ids: repositoryIds,
  });
}
