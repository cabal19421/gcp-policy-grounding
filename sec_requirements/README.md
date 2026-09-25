# `sec_requirements/` — the requirement authoring format

A security engineer adds an invariant to the gate by dropping a Markdown file in
this directory. No Python. This README is the canonical description of the
authoring format; the parser (`gcp_grounding/sec_parse.py`) implements exactly
what is written here, and the term language it accepts is listed below.

## Two stages

The gate turns Markdown into running z3 in two separate, auditable stages.

- **Stage 1 — compile** (`gcp-ground compile-requirements`). Each requirement
  document is parsed into a reviewable, git-committed artifact at
  `sec_requirements/compiled/<doc-slug>.promises.json`. The artifact is the
  review boundary: it records, for every promise, the exact Markdown sentence it
  came from, its polarity (`mode`), its tier (`state`), the vocabulary it names,
  and the typed AST. You commit this file and a reviewer reads it — it is how a
  human sees what the gate will actually enforce. Stage 1 is the only thing that
  writes `compiled/`; nothing commits it empty.
- **Stage 2 — evaluate.** Deterministic, LLM-free. The committed artifact is
  compiled to quantifier-free ground SMT (quantifiers are finitely unrolled over
  real records at evaluation time) and run in the same dispatch as the built-in
  checks, rendering through the same four `core.report` verdict buckets:
  `grounded`, `ungrounded`, `contradicted`, `unverified`.

To (re)compile every document in this directory:

```bash
gcp-ground compile-requirements
```

**What ships here.** This directory holds `TEMPLATE.md` and this README, and
discovery skips both — so that command over the shipped tree compiles **zero**
documents, and `sec_requirements/compiled/` exists only once you have written a
requirement of your own. The committed corpora to read instead are
`tests/fixtures/gcp/sec_requirements/` (the demo corpus, including one document
that is deliberately rejected) and the per-scenario corpora beside their
proposals under `examples/` — `examples/walkthrough/requirements.md` is the
smallest one, a single promise carried end to end by the root `README.md`
section "How the gate thinks".

## Document format

A requirement document is a `.md` file placed **directly** under a requirements
directory. Discovery skips `README.md` and `TEMPLATE.md`, and any file whose
name starts with a dot or an underscore.

### Frontmatter (optional)

If the very first line is exactly three hyphens (`---`), everything up to the
next line of exactly three hyphens is frontmatter. It is `key: value` lines only
— there is no YAML library behind it. The recognized keys are `domain`, `state`,
`mode` and `severity`; each supplies a **default** for every promise in the file
that does not set its own.

### Sections

Every level-2 heading (`## …`) opens a requirement section. Text before the
first heading is preamble and yields no promises.

The section's `source.text` is the first non-empty line after the heading that
is neither a fence nor a heading, taken verbatim with trailing whitespace
stripped; `source.line` is its 1-based line number. This is the sentence pinned
into the artifact.

A section may hold zero or more fenced blocks whose info string is `promise`
(opened by a triple-backtick fence). Each such block yields one promise. **A
section with prose but no promise block is never silently dropped** — it yields a
promise with `status: unverified` and the sentence quoted, so an author always
sees that the gate could not translate their requirement.

### Promise blocks

Inside a ` ```promise ` block, each line is either a `key: value` header or part
of the indented `smt:` body:

- `id:` — **required**, matches `^[a-z0-9][a-z0-9-]*$`, unique across the
  document.
- `mode:` — `assert_satisfiable` (the pattern must be able to hold) or `refute`
  (the pattern must not hold). Omitting the polarity would let a compiler
  silently invert security semantics, so it is explicit.
- `domain:` — one of `iam`, `vpc_firewall`, `cloud_armor`, `org_policy`,
  `hier_firewall`, `vpc_sc`.
- `state:` — `proposal`, `pair` or `estate`; decides which inputs the rule needs.
- `severity:` — a free-form label. It does not move a verdict between buckets.
- `vocab:` — repeatable, written `vocab: <kind> <value>` with kind in `role`,
  `permission`, `principal`, `constraint` or `resource_type_ref`. Each value is
  grounded through the same existence reasoner (with did-you-mean suggestions)
  that catches a typo'd role in a policy, before the promise is admitted.
- `note:` — repeatable free text.
- `smt:` — **last**. Every following line indented by two or more spaces is the
  AST body, in line-oriented prefix notation, two spaces per nesting level. Tabs
  are rejected.

Any header key set on a promise overrides the frontmatter default for that
promise only.

## The term language

The AST is a closed, typed prefix notation — never eval'd Python. Each node
keyword's children are the more-indented lines beneath it.

Logical nodes:

- `true`, `false`
- `not` — 1 child
- `and`, `or` — 1 or more children
- `implies` — 2 children
- `atmost <int>`, `atleast <int>` — 1 or more children
- `forall <var> in <collection>`, `exists <var> in <collection>` — 1 child

Leaf predicates:

- `in <term> set[...]`
- `cmp <eq|ne|lt|le|gt|ge> <term> <term>`
- `prefix <term> "s"`, `suffix <term> "s"`, `contains <term> "s"`
- `cidr_contains <term> <term>`
- `port_in <term> <lo:int> <hi:int>`
- `cel "<expression>"`

Terms:

- `field <var>.<name>`
- `str "..."`, `int N`, `bool true|false`
- `ip4 "10.0.0.0"`, `cidr "0.0.0.0/0"`, `port N`

## Collections

This is the full registry — the four base collections the compiler ships
(`gcp_grounding/sec_ast.py`) plus the eleven the domain layer registers
(`gcp_grounding/sec_domains.py`), which is installed. It is the same table the
root `README.md` prints, and a test compares both copies against the
collections those two modules register, so neither can drift:

| Policy surface | Collection | Tier | Fields (`name:Sort`) |
| --- | --- | --- | --- |
| IAM allow policy | `iam_bindings` | proposal | `role:Str`, `member:Str`, `condition:Str`, `has_condition:Bool` |
| IAM allow policy, old vs new | `new_iam_bindings` / `old_iam_bindings` | pair | same four fields |
| IAM custom role | `proposed_role_permissions` | proposal | `role:Str`, `permission:Str` |
| IAM deny policy (v2) | `deny_rules` | proposal | `policy:Str`, `rule_index:Int`, `denied_principal:Str`, `permission:Str`, `has_principal_exceptions:Bool`, `has_condition:Bool`, `condition:Str` |
| IAM deny policy (v2) | `deny_rule_exceptions` | proposal | `policy:Str`, `rule_index:Int`, `exception_principal:Str` |
| Organization Policy, per document | `org_policy_rules` | proposal | `constraint:Str`, `is_list:Bool`, `enforce:Bool`, `value:Str` |
| Organization Policy, effective fold | `effective_org_policy_bool` | estate | `node:Str`, `constraint:Str`, `enforce:Bool` |
| Organization Policy, effective fold | `effective_org_policy_values` | estate | `node:Str`, `constraint:Str`, `polarity:Str`, `value:Str`, `all_values:Bool` |
| VPC firewall rule, proposed | `proposed_firewall_rules` | proposal | `name:Str`, `network:Str`, `direction:Str`, `action:Str`, `priority:Int`, `disabled:Bool`, `source_range:Cidr`, `source_range_mask:Ip4`, `destination_range:Cidr`, `destination_range_mask:Ip4`, `source_tag:Str`, `target_tag:Str`, `protocol:Proto`, `port:Port` |
| VPC firewall rule, in the estate | `firewall_rules` | estate | the same fourteen fields |
| Hierarchical firewall rule | `hier_firewall_rules` | estate | `policy:Str`, `node:Str`, `priority:Int`, `action:Str`, `direction:Str`, `src_range:Cidr`, `src_range_mask:Ip4`, `protocol:Proto`, `port:Port` |
| Cloud Armor rule | `armor_rules` | proposal | `policy:Str`, `priority:Int`, `action:Str`, `preview:Bool`, `src_range:Cidr`, `src_range_mask:Ip4`, `expr:Str` |
| VPC-SC perimeter membership | `perimeter_resources` | proposal | `perimeter:Str`, `resource:Str`, `section:Str` |
| VPC-SC restricted services | `perimeter_restricted_services` | proposal | `perimeter:Str`, `service:Str`, `section:Str` |

The term language is **not** IAM-only. Any collection in neither half of the
registry is unregistered, and a promise naming it is `unverified` naming the
collection — never a false pass.

Every `Cidr` field declares a companion `<field>_mask` of sort `Ip4`, and a
promise naming a `Cidr` field whose collection lacks that companion is refused
when its AST is validated — a range without its mask is half a fact.

## The no-guessing contract

The compiler never guesses. A sentence the term language cannot express becomes a
promise with `status: unverified` and the exact sentence quoted — not an
approximate translation and not a silent drop. The same is true when a `vocab:`
value fails to ground, when a promise names an unregistered collection, when a
required snapshot category was not captured, when an encoding (e.g. a `cel`
condition) is unsupported, or when z3 is not installed. The gate's only verdict
channels are the four buckets, and every uncertain path lands in
`unverified` naming its reason.
