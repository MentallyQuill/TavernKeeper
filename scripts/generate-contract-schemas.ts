import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { z, type ZodType } from "zod";
import { format } from "prettier";

import {
  ReportIndexV5Schema,
  ScanReportV5Schema,
} from "../src/contracts/reports-v5.js";
import {
  TargetManifestV2Schema,
  TargetManifestV3Schema,
} from "../src/contracts/targets.js";

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
    file: "tavernary-targets.v3.schema.json",
    id: "https://tavernary.org/schemas/tavernkeeper-targets.v3.schema.json",
    title: "TavernKeeper V3 ranked scan target manifest",
    schema: TargetManifestV3Schema,
  },
  {
    file: "scan-report.v5.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/scan-report.v5.schema.json",
    title: "TavernKeeper V5 contextual scan report",
    schema: ScanReportV5Schema,
  },
  {
    file: "report-index.v5.schema.json",
    id: "https://mentallyquill.github.io/TavernKeeper/schemas/report-index.v5.schema.json",
    title: "TavernKeeper V5 contextual preferred report index",
    schema: ReportIndexV5Schema,
  },
];

export function buildContractSchemas() {
  return contracts.map((contract) => {
    const generated = z.toJSONSchema(contract.schema, { target: "draft-7" });
    const { $schema, ...body } = generated;
    const policyConditions =
      contract.file === "scan-report.v5.schema.json"
        ? {
            allOf: [
              {
                if: {
                  properties: {
                    contextual_review_policy_version: { const: "3" },
                  },
                  required: ["contextual_review_policy_version"],
                },
                then: {
                  properties: {
                    prompt_version: { const: "contextual-review-v6" },
                    assessment_schema_version: {
                      const: "contextual-assessment-v2",
                    },
                    assessments: {
                      items: { required: ["risk_exposure"] },
                    },
                    observations: {
                      items: { required: ["risk_exposure"] },
                    },
                  },
                },
              },
            ],
          }
        : {};
    return {
      file: contract.file,
      document: {
        $schema,
        $id: contract.id,
        title: contract.title,
        ...body,
        ...policyConditions,
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
