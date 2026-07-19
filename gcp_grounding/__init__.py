"""gcp-policy-grounding — a neuro-symbolic grounding gate for GCP IAM,
Organization Policy, and the Terraform that generates them.

Vocabulary existence is decided by a Datalog pass over a frozen snapshot of
the GCP estate; satisfiability/comparison questions (CEL conditions,
policy-subset proofs) go to z3 when available. Every check lands in one of
four honest buckets: grounded / ungrounded / contradicted / unverified.
"""

__version__ = "0.1.0"
