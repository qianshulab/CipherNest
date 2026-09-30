export function visibleListRows<T extends { id: string }>(
  entries: readonly T[],
  visibleCount: number,
  selectedId: string | null,
): { page: readonly T[]; selectedBeyondPage: T | null } {
  const page = entries.slice(0, Math.max(0, visibleCount));
  if (!selectedId || page.some((entry) => entry.id === selectedId)) {
    return { page, selectedBeyondPage: null };
  }
  return {
    page,
    selectedBeyondPage: entries.find((entry) => entry.id === selectedId) ?? null,
  };
}
