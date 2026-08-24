import type {
  ReportIndexEntryV5,
  ReportIndexV5,
} from "../contracts/reports-v5.js";

export interface ReportRepositoryIdentity {
  provider: ReportIndexEntryV5["provider"];
  repository_id: number;
}

export function compareReportPreference(
  left: ReportIndexEntryV5,
  right: ReportIndexEntryV5,
) {
  if (left.report_version !== right.report_version)
    return left.report_version - right.report_version;
  const time = Date.parse(left.completed_at) - Date.parse(right.completed_at);
  return time === 0 ? left.report_id.localeCompare(right.report_id) : time;
}

export function preferredRepositoryReport(
  index: ReportIndexV5,
  identity: ReportRepositoryIdentity,
) {
  return index.reports
    .filter(
      (report) =>
        report.provider === identity.provider &&
        report.repository_id === identity.repository_id,
    )
    .sort((left, right) => compareReportPreference(right, left))[0];
}

export function nextRepositoryReportLineage(
  index: ReportIndexV5,
  identity: ReportRepositoryIdentity,
) {
  const preferred = preferredRepositoryReport(index, identity);
  return {
    report_version: (preferred?.report_version ?? 0) + 1,
    supersedes_report_id: preferred?.report_id ?? null,
  };
}
