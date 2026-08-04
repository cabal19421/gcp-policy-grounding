# The benign session — what "normal" looks like

Every document in this directory is a payload of the twelve-proposal script in
`tests/test_gcp_agentic_benign.py`: one SRE onboarding a new data pipeline over
a single working session. Nothing here is adversarial, nothing here is a
near-miss, and the gate is asserted to be **byte-silent** across all of it.

The value of the corpus is that a reviewer can read it. A false-positive budget
whose inputs live only inside a Python literal cannot be audited — "is the gate
right to stay quiet about this?" is a question about the documents, not about
the test. So they are committed as files, in the order the session writes them:

| # | file | lands as | why it is benign |
|---|------|----------|------------------|
| 1 | `readme_pipeline.md` | `README.md` | not a policy document at all |
| 2 | `iam_policy_initial.json` | `pipeline/iam.policy.json` | a real role granted to a real group |
| 3 | `iam_policy_with_job_user.json` | `pipeline/iam.policy.json` | one more real role for the ETL service account |
| 4 | `orgpolicy_shielded_vm.json` | `pipeline/orgpolicy.policy.json` | a boolean constraint used boolean-typed |
| 5 | `app_settings.json` | `app/settings.json` | `.json`, but no policy kind — the gate must abstain |
| 6 | `tfplan_iam_member.json` | `infra/plan.tfplan.json` | a plan creating one real binding |
| 7 | `tfplan_custom_role.json` | `infra/custom_role.tfplan.json` | a custom role over permissions that all exist |
| 8 | `iam_policy_conditional.json` | `pipeline/analytics.iam.policy.json` | a satisfiable time window |
| 9 | `iam_policy_empty.json` | `pipeline/staging.iam.policy.json` | an allow policy that grants nothing |
| 10 | `tfplan_firewall_narrow.json` | `pipeline/firewall.tfplan.json` | `0.0.0.0/0` narrowed to `10.0.0.0/8` |
| 11 | `main_py.txt` | `app/main.py` | not a policy document at all |
| 12 | `iam_policy_shrunk.json` | `pipeline/iam.policy.json` | strictly fewer grants than revision 3 |

`main_py.txt` carries a `.txt` suffix on purpose. It is the *content* of an
application source file, not a module of this repo: committing it as `.py`
would put an unimportable snippet on a static analyser's path, and its imports
(a fictional `ingest` package belonging to the fictional SRE's application)
would be reported as undefined symbols of *this* checkout. The suffix keeps it
readable and inert; turn 11 writes it to `app/main.py` inside the fake agent's
throwaway working tree, which is the only place it is ever a `.py` file.
