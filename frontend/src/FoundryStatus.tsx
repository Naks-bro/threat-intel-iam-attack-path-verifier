function tone(value: string) {
  const normalized = value.toLowerCase();
  if (["pass", "succeeded", "mapped", "ready", "available", "accepted"].includes(normalized)) return "positive";
  if (["fail", "failed", "rejected", "unmapped", "unavailable", "error"].includes(normalized)) return "negative";
  if (["experimental", "partial", "needs_review", "proposed", "empty", "incomplete"].includes(normalized)) return "warning";
  return "neutral";
}

export function StatusTag({ value }: { value: string }) {
  return <span className={`status-tag is-${tone(value)}`}>{value.replaceAll("_", " ")}</span>;
}
