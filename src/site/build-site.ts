import { copyFile, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

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

const ROOT_PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'none'; img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'">
  <title>TavernKeeper reports</title>
</head>
<body>
  <main>
    <h1>TavernKeeper reports</h1>
    <p>Immutable, sanitized scan reports published for Tavernary.</p>
    <p><a href="reports/index.json">Report index</a></p>
  </main>
</body>
</html>
`;

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
  ];
  validateOutput(root, output, sources);

  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  await copyTree(sources[0]!, join(output, "reports"));
  await copyTree(sources[1]!, join(output, "schemas"));
  await copyTree(sources[2]!, join(output, "rules"));
  await writeFile(join(output, "index.html"), ROOT_PAGE);
  await writeFile(join(output, ".nojekyll"), "");

  return { output, files: await listFiles(output) };
}
