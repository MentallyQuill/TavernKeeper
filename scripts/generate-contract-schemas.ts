import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { z, type ZodType } from "zod";
import { format } from "prettier";

import {
  ReportIndexV4Schema,
  ReportIndexV2Schema,
  ScanReportV4Schema,
  ScanReportV2Schema,
} from "../src/contracts/reports.js";
import { TargetManifestV2Schema } from "../src/contracts/targets.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const contracts: Array<{
  file: string;
  id: string;
  title: string;
  schema: ZodType;
}> = [
  {
    file: "tavernary-targets.v2.schema.json",
    id: "https://tavernary.org/schemas/tavernkeeper-targets.v2.schema.json",
    title: "TavernKeeper V2 scan target manifest",
    schema: TargetManifestV2Schema,
  },
  {
    file: "scan-report.v2.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/scan-report.v2.schema.json",
    title: "TavernKeeper V2 complete automated scan report",
    schema: ScanReportV2Schema,
  },
  {
    file: "report-index.v2.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/report-index.v2.schema.json",
    title: "TavernKeeper V2 preferred report index",
    schema: ReportIndexV2Schema,
  },
  {
    file: "scan-report.v4.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/scan-report.v4.schema.json",
    title: "TavernKeeper V4 deterministic scan report",
    schema: ScanReportV4Schema,
  },
  {
    file: "report-index.v4.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/report-index.v4.schema.json",
    title: "TavernKeeper V4 deterministic preferred report index",
    schema: ReportIndexV4Schema,
  },
];

export function buildContractSchemas() {
  return contracts.map((contract) => {
    const generated = z.toJSONSchema(contract.schema, { target: "draft-7" });
    const { $schema, ...body } = generated;
    return {
      file: contract.file,
      document: {
        $schema,
        $id: contract.id,
        title: contract.title,
        ...body,
      },
    };
  });
}

export function serializeContractSchema(document: object) {
  return format(JSON.stringify(document), { parser: "json" });
}

export async function writeContractSchemas() {
  await Promise.all(
    buildContractSchemas().map(({ file, document }) =>
      serializeContractSchema(document).then((serialized) =>
        writeFile(resolve(root, "schemas", file), serialized, "utf8"),
      ),
    ),
  );
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await writeContractSchemas();
}
