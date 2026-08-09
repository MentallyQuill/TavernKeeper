import { existsSync, readFileSync } from "node:fs";

try {
  const path = process.argv[2];
  if (typeof path !== "string" || path.length === 0) process.exitCode = 1;
  else if (!existsSync(path)) process.stdout.write("0");
  else {
    const bundle = JSON.parse(readFileSync(path, "utf8"));
    const ids = bundle?.progress?.completed_group_ids;
    if (
      !Array.isArray(ids) ||
      ids.some((id) => typeof id !== "string" || !/^[0-9a-f]{64}$/u.test(id)) ||
      new Set(ids).size !== ids.length
    )
      process.exitCode = 1;
    else process.stdout.write(String(ids.length));
  }
} catch {
  process.exitCode = 1;
}
