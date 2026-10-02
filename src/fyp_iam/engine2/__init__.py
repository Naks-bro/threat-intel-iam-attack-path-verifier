"""Engine 2: synthetic IAM records to a portable graph.

The normalizer records permissions boundaries, exact service trusts, and which
policy layers it actually read. A tested read-only IAM policy template is not attached.
Live AWS collection and Neo4j persistence are not implemented.
"""
