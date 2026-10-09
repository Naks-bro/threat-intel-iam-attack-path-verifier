type NexusKind = "candidate" | "denied" | "needs_context" | "policy_text";

export type TimelineStation = {
  key: string;
  label: string;
  detail: string;
  nexus: {
    kind: NexusKind;
    action: string;
    targetLabel: string;
    extraPaths: number;
  } | null;
};

const BRANCH_Y: Record<number, number> = { 0: 72, 1: 292 };

export function TimelineCanvas({
  snapshotId,
  stations,
  selectedKey,
  onSelect,
}: {
  snapshotId: string;
  stations: TimelineStation[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
}) {
  return (
    <figure className="timeline-canvas" aria-labelledby="timeline-title">
      <div className="timeline-canvas-heading">
        <p className="section-code">Timeline / main IAM graph</p>
        <h2 id="timeline-title">Timeline</h2>
        <p>
          One snapshot, one line. A colored line leaving it is a nexus event: a possible branch for that identity. It is not proof the account is exploitable.
        </p>
      </div>
      <svg viewBox="0 0 880 360" role="group" aria-label="Timeline and nexus events">
        <line className="timeline-rail" x1="36" y1="180" x2="844" y2="180" />
        <text className="timeline-rail-label" x="36" y="164">Timeline</text>
        {stations.map((station, index) => {
          const x = 160 + index * 280;
          const branchY = BRANCH_Y[index] ?? 72;
          const dim = selectedKey !== null && selectedKey !== station.key;
          return (
            <g key={station.key} className={dim ? "timeline-dim" : undefined}>
              {station.nexus ? (
                <g>
                  <path
                    className={`nexus-line nexus-${station.nexus.kind}`}
                    d={`M ${x} 180 C ${x} ${branchY}, ${x + 90} ${branchY}, ${x + 150} ${branchY}`}
                  />
                  <text className={`nexus-label nexus-${station.nexus.kind}`} x={x + 18} y={branchY < 180 ? branchY - 28 : branchY + 36}>
                    Nexus event
                  </text>
                  <text className="nexus-action" x={x + 18} y={branchY < 180 ? branchY - 12 : branchY + 52}>
                    {station.nexus.action}{station.nexus.extraPaths > 0 ? ` +${station.nexus.extraPaths}` : ""}
                  </text>
                </g>
              ) : null}
              <g
                role="button"
                tabIndex={0}
                aria-pressed={selectedKey === station.key}
                aria-label={station.nexus
                  ? `${station.label}, nexus event, ${station.nexus.action}`
                  : `${station.label}, on the timeline, no nexus event`}
                onClick={() => onSelect(station.key)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(station.key);
                  }
                }}
              >
                <circle className="timeline-station" cx={x} cy={180} r={8} />
                <text className="timeline-station-label" x={x} y={208}>{station.label}</text>
                <text className="timeline-station-detail" x={x} y={226}>{station.detail}</text>
              </g>
              {station.nexus ? (
                <g
                  role="button"
                  tabIndex={0}
                  aria-pressed={selectedKey === station.key}
                  aria-label={`Open nexus event from ${station.label} to ${station.nexus.targetLabel}`}
                  onClick={() => onSelect(station.key)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(station.key);
                    }
                  }}
                >
                  <rect className={`nexus-node nexus-${station.nexus.kind}`} x={x + 150} y={branchY - 18} width={148} height={36} />
                  <text className="nexus-node-label" x={x + 224} y={branchY + 4}>{station.nexus.targetLabel}</text>
                </g>
              ) : (
                <text className="timeline-station-detail" x={x} y={246}>No nexus event</text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption>
        <ul className="timeline-legend">
          <li><span className="legend-swatch legend-timeline" aria-hidden="true" /> Timeline, snapshot <code>{snapshotId}</code></li>
          <li><span className="legend-swatch legend-candidate" aria-hidden="true" /> Nexus event, candidate in the fixture</li>
          <li><span className="legend-swatch legend-denied" aria-hidden="true" /> Nexus event, denied in the fixture</li>
          <li><span className="legend-swatch legend-context" aria-hidden="true" /> Nexus event, needs more context</li>
          <li><span className="legend-swatch legend-policy_text" aria-hidden="true" /> Nexus event, policy text only</li>
        </ul>
        <p>Color is a label, not a severity score. An identity with no colored line was tested and produced no branch for this rule.</p>
      </figcaption>
    </figure>
  );
}
