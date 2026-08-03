import { runInNewContext } from "node:vm";

import { describe, expect, test } from "vitest";

import { REPORT_SEARCH_SCRIPT } from "../src/site/search-script.js";

class ElementDouble {
  value = "";
  hidden = false;
  textContent = "";
  readonly dataset: Record<string, string>;
  readonly #listeners = new Map<string, Array<() => void>>();

  constructor(dataset: Record<string, string> = {}) {
    this.dataset = dataset;
  }

  addEventListener(type: string, listener: () => void) {
    const listeners = this.#listeners.get(type) ?? [];
    listeners.push(listener);
    this.#listeners.set(type, listeners);
  }

  dispatch(type: string) {
    for (const listener of this.#listeners.get(type) ?? []) listener();
  }

  click() {
    this.dispatch("click");
  }
}

describe("report directory search", () => {
  test("filters by every typed term and highest risk without changing the query", () => {
    const root = new ElementDouble();
    const search = new ElementDouble();
    const risk = new ElementDouble();
    risk.value = "all";
    const clear = new ElementDouble();
    const status = new ElementDouble();
    const empty = new ElementDouble();
    const recursion = new ElementDouble({
      reportCard: "",
      risk: "low",
      search:
        "mentallyquill recursion 1bce1fa no material or high-risk concern",
    });
    const wandlight = new ElementDouble({
      reportCard: "",
      risk: "material",
      search: "mentallyquill wandlight 2d4f818 material concern",
    });
    const elements = new Map<string, ElementDouble>([
      ["report-query", search],
      ["report-risk", risk],
      ["report-clear", clear],
      ["report-status", status],
      ["report-empty", empty],
    ]);

    runInNewContext(REPORT_SEARCH_SCRIPT, {
      document: {
        querySelector: (selector: string) =>
          selector === "[data-report-search]" ? root : null,
        querySelectorAll: (selector: string) =>
          selector === "[data-report-card]" ? [recursion, wandlight] : [],
        getElementById: (id: string) => elements.get(id) ?? null,
      },
    });

    expect(status.textContent).toBe("2 reports shown");
    search.value = "Recursion 1bce";
    search.dispatch("input");
    expect(search.value).toBe("Recursion 1bce");
    expect(recursion.hidden).toBe(false);
    expect(wandlight.hidden).toBe(true);
    expect(status.textContent).toBe("1 report shown");

    search.value = "";
    risk.value = "material";
    risk.dispatch("change");
    expect(recursion.hidden).toBe(true);
    expect(wandlight.hidden).toBe(false);

    clear.click();
    expect(search.value).toBe("");
    expect(risk.value).toBe("all");
    expect(recursion.hidden).toBe(false);
    expect(wandlight.hidden).toBe(false);
    expect(empty.hidden).toBe(true);
  });
});
