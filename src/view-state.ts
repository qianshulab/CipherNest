interface FocusPosition {
  element: HTMLElement;
  id: string;
  key: string | undefined;
  selectionStart: number | null;
  selectionEnd: number | null;
  selectionDirection: "forward" | "backward" | "none" | null;
}

export interface ViewPosition {
  view: string | undefined;
  scroll: Map<string, number>;
  focus: FocusPosition | null;
}

function textSelection(element: HTMLElement): Pick<FocusPosition, "selectionStart" | "selectionEnd" | "selectionDirection"> {
  if (
    (typeof HTMLInputElement !== "undefined" && element instanceof HTMLInputElement)
    || (typeof HTMLTextAreaElement !== "undefined" && element instanceof HTMLTextAreaElement)
  ) {
    return {
      selectionStart: element.selectionStart,
      selectionEnd: element.selectionEnd,
      selectionDirection: element.selectionDirection,
    };
  }
  return { selectionStart: null, selectionEnd: null, selectionDirection: null };
}

export function captureViewPosition(root: HTMLElement): ViewPosition {
  const active = document.activeElement;
  const focused = active instanceof HTMLElement && root.contains(active) ? active : null;
  const scroll = new Map<string, number>();
  root.querySelectorAll<HTMLElement>("[data-scroll-key]").forEach((element) => {
    if (element.dataset.scrollKey) scroll.set(element.dataset.scrollKey, element.scrollTop);
  });
  return {
    view: root.querySelector<HTMLElement>(".app-shell")?.dataset.view,
    scroll,
    focus: focused
      ? { element: focused, id: focused.id, key: focused.dataset.focusKey, ...textSelection(focused) }
      : null,
  };
}

export function restoreViewPosition(root: HTMLElement, position: ViewPosition, view: string): void {
  if (position.view !== view) return;
  root.querySelectorAll<HTMLElement>("[data-scroll-key]").forEach((element) => {
    const offset = position.scroll.get(element.dataset.scrollKey ?? "");
    if (offset !== undefined) element.scrollTop = offset;
  });

  const saved = position.focus;
  if (!saved) return;
  const target = saved.element.isConnected && root.contains(saved.element)
    ? saved.element
    : Array.from(root.querySelectorAll<HTMLElement>("[id], [data-focus-key]")).find((element) =>
      (saved.id && element.id === saved.id) || (saved.key && element.dataset.focusKey === saved.key),
    );
  if (!target || target.matches(":disabled, [hidden], [aria-hidden='true']")) return;
  target.focus({ preventScroll: true });
  if (
    saved.selectionStart !== null
    && saved.selectionEnd !== null
    && ((typeof HTMLInputElement !== "undefined" && target instanceof HTMLInputElement)
      || (typeof HTMLTextAreaElement !== "undefined" && target instanceof HTMLTextAreaElement))
  ) {
    try {
      target.setSelectionRange(saved.selectionStart, saved.selectionEnd, saved.selectionDirection ?? "none");
    } catch {
      // Some input types do not support a text selection.
    }
  }
}
