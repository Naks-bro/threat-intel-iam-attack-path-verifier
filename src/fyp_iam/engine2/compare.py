"""Compare derived capability edges without treating ids as authorization proof."""

from fyp_iam.contracts.models import EdgeType, IAMGraphSnapshot

_CAPABILITY = frozenset(
    {
        EdgeType.CAN_ASSUME,
        EdgeType.CAN_ACCESS,
        EdgeType.TRUSTS,
        EdgeType.HAS_BOUNDARY,
    }
)


def capability_pairs(snapshot: IAMGraphSnapshot) -> frozenset[tuple[str, str, str, str]]:
    """Return edge type, source, target, and effect for derived capabilities.

    Policy attachment edges are omitted. Equal pairs do not prove exploitability.
    """
    return frozenset(
        (edge.edge_type.value, edge.source_id, edge.target_id, edge.effect.value)
        for edge in snapshot.edges
        if edge.edge_type in _CAPABILITY
    )


def pair_scores(
    expected: frozenset[tuple[str, str, str, str]],
    actual: frozenset[tuple[str, str, str, str]],
) -> tuple[float, float]:
    """Return precision and recall for capability pairs.

    Precision is 1 when the normalizer emits no pairs. Recall is 1 when the
    fixture has no pairs. A perfect score is not exploitability.
    """
    matched = len(expected & actual)
    precision = 1.0 if not actual else matched / len(actual)
    recall = 1.0 if not expected else matched / len(expected)
    return precision, recall
