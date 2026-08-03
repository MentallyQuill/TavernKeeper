export const REPORT_SEARCH_SCRIPT = `(() => {
  const root = document.querySelector("[data-report-search]");
  if (!root) return;

  const query = document.getElementById("report-query");
  const risk = document.getElementById("report-risk");
  const clear = document.getElementById("report-clear");
  const status = document.getElementById("report-status");
  const empty = document.getElementById("report-empty");
  const cards = Array.from(document.querySelectorAll("[data-report-card]"));
  if (!query || !risk || !clear || !status || !empty) return;

  const apply = () => {
    const terms = query.value
      .toLocaleLowerCase()
      .split(/\\s+/u)
      .filter(Boolean);
    let shown = 0;
    for (const card of cards) {
      const text = card.dataset.search || "";
      const matchesQuery = terms.every((term) => text.includes(term));
      const matchesRisk = risk.value === "all" || card.dataset.risk === risk.value;
      card.hidden = !(matchesQuery && matchesRisk);
      if (!card.hidden) shown += 1;
    }
    status.textContent = shown === 1 ? "1 report shown" : shown + " reports shown";
    empty.hidden = shown !== 0;
  };

  query.addEventListener("input", apply);
  risk.addEventListener("change", apply);
  clear.addEventListener("click", () => {
    query.value = "";
    risk.value = "all";
    apply();
  });
  apply();
})();
`;
