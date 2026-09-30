import { afterEach, describe, expect, it, vi } from "vitest";
import { captureViewPosition, restoreViewPosition } from "./view-state";

class TestElement {
  dataset: Record<string, string> = {};
  id = "";
  isConnected = true;
  scrollTop = 0;
  focused = false;
  children: TestElement[] = [];

  contains(element: TestElement): boolean {
    return this === element || this.children.some((child) => child.contains(element));
  }

  querySelector(selector: string): TestElement | null {
    return selector === ".app-shell" ? this.children.find((child) => child.dataset.view) ?? null : null;
  }

  querySelectorAll(selector: string): TestElement[] {
    const descendants = this.children.flatMap((child) => [child, ...child.querySelectorAll("*")]);
    if (selector === "[data-scroll-key]") return descendants.filter((child) => child.dataset.scrollKey);
    if (selector === "[id], [data-focus-key]") return descendants.filter((child) => child.id || child.dataset.focusKey);
    return descendants;
  }

  matches(): boolean {
    return false;
  }

  focus(): void {
    this.focused = true;
  }
}

class TestInput extends TestElement {
  selectionStart: number | null = 0;
  selectionEnd: number | null = 0;
  selectionDirection: "forward" | "backward" | "none" | null = "none";

  setSelectionRange(start: number, end: number, direction: "forward" | "backward" | "none"): void {
    this.selectionStart = start;
    this.selectionEnd = end;
    this.selectionDirection = direction;
  }
}

function setupDom(activeElement: TestElement): void {
  vi.stubGlobal("HTMLElement", TestElement);
  vi.stubGlobal("HTMLInputElement", TestInput);
  vi.stubGlobal("HTMLTextAreaElement", TestInput);
  vi.stubGlobal("document", { activeElement });
}

function view(viewName: string, focused: TestElement, offset: number): TestElement {
  const root = new TestElement();
  const shell = new TestElement();
  shell.dataset.view = viewName;
  const list = new TestElement();
  list.dataset.scrollKey = "entry-list";
  list.scrollTop = offset;
  list.children.push(focused);
  shell.children.push(list);
  root.children.push(shell);
  return root;
}

afterEach(() => vi.unstubAllGlobals());

describe("view state after a full shell redraw", () => {
  it("keeps a large list at the same scroll position and restores the focused row", () => {
    const oldRow = new TestElement();
    oldRow.dataset.focusKey = "entry-abc-select";
    setupDom(oldRow);
    const saved = captureViewPosition(view("all", oldRow, 1290) as unknown as HTMLElement);
    oldRow.isConnected = false;

    const newRow = new TestElement();
    newRow.dataset.focusKey = "entry-abc-select";
    const next = view("all", newRow, 0);
    restoreViewPosition(next as unknown as HTMLElement, saved, "all");

    expect(next.children[0]?.children[0]?.scrollTop).toBe(1290);
    expect(newRow.focused).toBe(true);
  });

  it("keeps the search caret while results refresh", () => {
    const oldSearch = new TestInput();
    oldSearch.id = "vault-search";
    oldSearch.selectionStart = 2;
    oldSearch.selectionEnd = 2;
    setupDom(oldSearch);
    const saved = captureViewPosition(view("all", oldSearch, 0) as unknown as HTMLElement);
    oldSearch.isConnected = false;

    const newSearch = new TestInput();
    newSearch.id = "vault-search";
    restoreViewPosition(view("all", newSearch, 0) as unknown as HTMLElement, saved, "all");

    expect(newSearch.focused).toBe(true);
    expect(newSearch.selectionStart).toBe(2);
  });

  it("does not carry scroll or focus into another page", () => {
    const oldRow = new TestElement();
    oldRow.dataset.focusKey = "entry-abc-select";
    setupDom(oldRow);
    const saved = captureViewPosition(view("all", oldRow, 1290) as unknown as HTMLElement);

    const other = new TestElement();
    other.dataset.focusKey = "entry-abc-select";
    const next = view("settings", other, 0);
    restoreViewPosition(next as unknown as HTMLElement, saved, "settings");

    expect(next.children[0]?.children[0]?.scrollTop).toBe(0);
    expect(other.focused).toBe(false);
  });
});
