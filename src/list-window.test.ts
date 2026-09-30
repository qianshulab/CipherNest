import { describe, expect, it } from "vitest";

import { visibleListRows } from "./list-window";

describe("large entry list selection", () => {
  const entries = Array.from({ length: 10_000 }, (_, index) => ({ id: `entry-${index}` }));

  it("keeps an issue opened beyond the first page visible without rendering every row", () => {
    const result = visibleListRows(entries, 200, "entry-9999");
    expect(result.page).toHaveLength(200);
    expect(result.selectedBeyondPage?.id).toBe("entry-9999");
  });

  it("does not duplicate an entry already in the rendered page", () => {
    const result = visibleListRows(entries, 200, "entry-199");
    expect(result.selectedBeyondPage).toBeNull();
  });

  it("does not show a removed selection", () => {
    expect(visibleListRows(entries, 200, "deleted").selectedBeyondPage).toBeNull();
  });
});
