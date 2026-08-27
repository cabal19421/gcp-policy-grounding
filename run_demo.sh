#!/usr/bin/env bash
#
# run_demo.sh — run one README demo arc end to end, offline.
#
#   ./run_demo.sh --list      enumerate the scenarios (read from README.md's
#                             "The scenarios at a glance" table)
#   ./run_demo.sh <scenario>  run that scenario's arc: every command the
#                             README documents for it, in order, including
#                             the compile-requirements step its promises
#                             come from
#
# Every step carries the exit code the README documents. A DENIED step exits
# 1 BY DESIGN and the compile of the demo corpus exits 1 by design too, so
# there is deliberately no `set -e` over the steps: each step's exit is
# captured directly (never through a pipe), compared to the documented one,
# and the run ends with a scenario verdict — nonzero exit if, and only if,
# some step's observed exit diverged from what the README says it is.
#
# Plain bash plus awk. The only other thing it needs is the repo's own venv
# (`python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'`); with no
# venv present it falls back to `python3 -m gcp_grounding` from this checkout.

set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 2

README="$ROOT/README.md"

# The README's arcs name every input by its own flag and are documented
# offline, so an exported grounding variable — a snapshot, a requirements
# directory, a clock — would change what these steps decide and make their
# documented exits wrong. Drop them for this run; the shell that invoked us
# keeps its own. Scenario six re-pins the clock per step, exactly as the
# README's own commands for it do.
SCRUBBED=""
for _name in $(awk 'BEGIN { for (v in ENVIRON)
                                if (v ~ /^GCP_(GROUNDING|SEC)_/) print v }' \
              </dev/null); do
    unset "$_name"
    SCRUBBED="$SCRUBBED $_name"
done

# The clock the deny-policy scenario's own README commands pin: its estate
# judgments are snapshot reads a stale capture may not license, so the
# fixture's capture era is pinned exactly as the README pins it.
DENY_NOW="GCP_GROUNDING_NOW=2026-07-18T12:00:00Z"

# -- the gate command ---------------------------------------------------------

# $GCP_GROUND overrides (word-split on purpose: it may name an interpreter and
# its -m argument). Otherwise the repo venv's console script, then the venv's
# interpreter, then this checkout run in place.
if [ -n "${GCP_GROUND:-}" ]; then
    # shellcheck disable=SC2206
    GROUND=(${GCP_GROUND})
elif [ -x "$ROOT/.venv/bin/gcp-ground" ]; then
    GROUND=("$ROOT/.venv/bin/gcp-ground")
elif [ -x "$ROOT/.venv/bin/python" ]; then
    GROUND=("$ROOT/.venv/bin/python" -m gcp_grounding)
else
    GROUND=(python3 -m gcp_grounding)
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

# -- the scenario table, read from the README ---------------------------------

# One record per at-a-glance row: label, proposal cell, scenario cell, expect
# cell, tab separated. The labels this prints are the labels this runner
# accepts — `--list` fails loudly if the README names one no arc below runs.
readme_scenarios() {
    awk -F'|' '
        /^### The scenarios at a glance/ { inside = 1; next }
        inside && /^\|/ {
            label = $2; scen = $3; prop = $4; want = $5
            gsub(/`/, "", scen); gsub(/`/, "", prop); gsub(/`/, "", want)
            gsub(/^[ \t]+|[ \t]+$/, "", label)
            gsub(/^[ \t]+|[ \t]+$/, "", scen)
            gsub(/^[ \t]+|[ \t]+$/, "", prop)
            gsub(/^[ \t]+|[ \t]+$/, "", want)
            if (label == "#" || label ~ /^-+$/) next
            printf "%s\t%s\t%s\t%s\n", label, prop, scen, want
            rows = 1
            next
        }
        inside && rows { exit }
    ' "$README"
}

# -- steps --------------------------------------------------------------------

DRY=0          # 1 = count the arc's steps, run nothing
STEPS=0        # steps seen in the current arc
DIVERGED=0     # steps whose observed exit was not the documented one
INDEX=0        # step number being run
TOTAL=0        # steps in the arc being run

# step <expected-exit> <story> <command...>
step() {
    local want="$1"; shift
    local story="$1"; shift

    STEPS=$((STEPS + 1))
    if [ "$DRY" = 1 ]; then
        return 0
    fi

    INDEX=$((INDEX + 1))
    printf '\n=== step %d/%d — %s\n' "$INDEX" "$TOTAL" "$story"
    printf '    expected exit: %d\n' "$want"
    printf '    $ %s\n\n' "$*"

    "$@"
    local rc=$?

    if [ "$rc" = "$want" ]; then
        printf '\n--- step %d/%d: exit %d, as documented\n' "$INDEX" "$TOTAL" "$rc"
    else
        DIVERGED=$((DIVERGED + 1))
        printf '\n--- step %d/%d: DIVERGED — exit %d, the README documents %d\n' \
            "$INDEX" "$TOTAL" "$rc" "$want"
    fi
    return 0
}

# -- the compile steps (part of the arcs whose promises they compile) ---------

compile_demo() {
    step 1 "compile the demo corpus — exits 1 by design: one document names a hallucinated role, and a rejected promise fails the compile loudly" \
        "${GROUND[@]}" compile-requirements tests/fixtures/gcp/sec_requirements \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled
}

compile_roles() {
    step 0 "compile the custom-role scenario's one-promise corpus" \
        "${GROUND[@]}" compile-requirements examples/terraform-roles \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled-roles
}

compile_masked() {
    step 0 "compile the masked-deny scenario's one-promise corpus" \
        "${GROUND[@]}" compile-requirements examples/terraform-masked \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled-masked
}

compile_orgpolicy() {
    step 0 "compile the org-policy scenario's eleven-promise corpus" \
        "${GROUND[@]}" compile-requirements examples/terraform-orgpolicy \
        --snapshot examples/terraform-orgpolicy/snapshot.json --out demo/compiled-orgpolicy
}

compile_denypolicy() {
    step 0 "compile the deny-policy scenario's three-promise corpus" \
        "${GROUND[@]}" compile-requirements examples/terraform-denypolicy \
        --snapshot examples/terraform-denypolicy/snapshot.json --out demo/compiled-denypolicy
}

compile_walkthrough() {
    step 0 "compile the walkthrough's one-promise corpus — the artifact the 'How the gate thinks' section quotes" \
        "${GROUND[@]}" compile-requirements examples/walkthrough \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled-walkthrough
}

# -- the verify steps, one helper per scenario directory ----------------------

verify_roles() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-roles/$3" \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json \
        --terraform-state examples/terraform-roles/terraform.tfstate \
        --requirements demo/compiled-roles \
        --explain
}

verify_masked() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-masked/$3" \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json \
        --terraform-state examples/terraform-masked/terraform.tfstate \
        --explain
}

verify_masked_narrowed() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-masked/$3" \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json \
        --terraform-state examples/terraform-masked/terraform-after-removal.tfstate \
        --requirements demo/compiled-masked \
        --explain
}

verify_schema() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-schema/$3" \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json \
        --provider-schema examples/terraform-schema/provider-schema.json \
        --explain
}

verify_orgpolicy() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-orgpolicy/$3" \
        --snapshot examples/terraform-orgpolicy/snapshot.json \
        --terraform-state examples/terraform-orgpolicy/terraform.tfstate \
        --requirements demo/compiled-orgpolicy \
        --explain
}

verify_denypolicy() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" env "$DENY_NOW" "${GROUND[@]}" verify-policy \
        --proposal "examples/terraform-denypolicy/$3" \
        --snapshot examples/terraform-denypolicy/snapshot.json \
        --requirements demo/compiled-denypolicy \
        --explain
}

# The state file is named on the command line rather than left to sibling
# auto-detection: the section quotes this run's summary, and an auto-detected
# path prints absolute and layer '[auto]', which is not reproducible on
# another machine.
verify_walkthrough() {  # <expected-exit> <story> <proposal>
    step "$1" "$2" "${GROUND[@]}" verify-policy \
        --proposal "examples/walkthrough/$3" \
        --snapshot tests/fixtures/gcp/agentic_snapshot.json \
        --terraform-state examples/walkthrough/terraform.tfstate \
        --requirements demo/compiled-walkthrough \
        --explain
}

# -- the arcs -----------------------------------------------------------------

# Every label here is a label of the README's at-a-glance table, and every
# label of that table is a case here — `--list` proves the two agree.
arc() {
    case "$1" in
    1)
        compile_demo
        step 1 "the terraform finale: world-open SSH and roles/owner to an outsider, judged against state, snapshot and the compiled promises" \
            "${GROUND[@]}" verify-policy \
            --proposal examples/terraform/main.tf.json \
            --snapshot tests/fixtures/gcp/agentic_snapshot.json \
            --terraform-state examples/terraform/terraform.tfstate \
            --requirements demo/compiled \
            --explain
        ;;
    2a)
        compile_roles
        verify_roles 0 "case A: the swap's extra permission is harmless — surfaced as a warning, not blocked" proposal_a.tf.json
        ;;
    2b)
        compile_roles
        verify_roles 1 "case B: the extra permission is iam.serviceAccounts.actAs — the promise refuses" proposal_b.tf.json
        ;;
    3)
        verify_masked 1 "the accident: the deny removed, the dormant allow wakes up world-open" proposal.tf.json
        ;;
    3b)
        verify_masked 1 "the benign counterpart: the dead allow deleted — blocked too, because deletions are invisible without the pair tier" cleanup.tf.json
        ;;
    3c)
        compile_masked
        verify_masked_narrowed 0 "the remediation: the woken allow narrowed to exactly the two audited partner ranges" narrowed.tf.json
        ;;
    3d)
        compile_masked
        verify_masked_narrowed 1 "the smuggle: the two audited ranges plus one unaudited /28" narrowed_extra.tf.json
        ;;
    4)
        verify_schema 1 "the typo: src_ranges for source_ranges, with the did-you-mean naming the real attribute" proposal_typo.tf.json
        ;;
    4b)
        verify_schema 1 "the version skew: an attribute the captured provider schema does not define" proposal_newer.tf.json
        ;;
    4c)
        verify_schema 0 "the clean counterpart: every attribute resolves, so the schema family stays silent" proposal_ok.tf.json
        ;;
    4d)
        step 0 "a schema policy configured with no schema supplied: the gate abstains by name instead of passing in silence" \
            "${GROUND[@]}" verify-policy \
            --proposal examples/terraform-schema/proposal_ok.tf.json \
            --snapshot tests/fixtures/gcp/agentic_snapshot.json \
            --schema-policy block
        ;;
    5)
        compile_orgpolicy
        verify_orgpolicy 0 "the compliant estate: all eleven catalogue-named promises hold" base.tf.json
        ;;
    5a)
        compile_orgpolicy
        verify_orgpolicy 1 "serial console re-enabled and a VM allowed an external IP" proposal_serial_and_publicip.tf.json
        ;;
    5b)
        compile_orgpolicy
        verify_orgpolicy 1 "Cloud Run ingress opened to 'all'" proposal_run_ingress_public.tf.json
        ;;
    5c)
        compile_orgpolicy
        verify_orgpolicy 1 "external VPC peering allowed and internet-NEG enforcement dropped" proposal_peering_and_neg.tf.json
        ;;
    5d)
        compile_orgpolicy
        verify_orgpolicy 1 "public-access prevention off and an outside contact domain" proposal_storage_contacts.tf.json
        ;;
    5e)
        compile_orgpolicy
        verify_orgpolicy 1 "roles/owner to an outsider plus a token-creator grant" proposal_admin_impersonation.tf.json
        ;;
    5f)
        compile_orgpolicy
        verify_orgpolicy 1 "an egress allow to 0.0.0.0/0 — the promise and the built-in condemn it from two directions" proposal_egress_world.tf.json
        ;;
    5g)
        compile_orgpolicy
        verify_orgpolicy 0 "the benign counterpart: the ingress allowlist tightened" proposal_benign.tf.json
        ;;
    6)
        compile_denypolicy
        verify_denypolicy 0 "the compliant estate: the guardrail, the grant it masks, and the org-policy restatement" plan_base.json
        ;;
    6a)
        compile_denypolicy
        verify_denypolicy 1 "the carve-out: payroll CI added to the guardrail's exceptionPrincipals" plan_threading.json
        ;;
    6b)
        compile_denypolicy
        verify_denypolicy 1 "the removal: a rendered plan deleting the deny policy — the dormant grant wakes" plan_remove_deny.json
        ;;
    6c)
        compile_denypolicy
        verify_denypolicy 1 "the hygiene sweep: a folder-level reset, judged over the effective collection" plan_reset_payments.json
        ;;
    w)
        compile_walkthrough
        verify_walkthrough 1 "the worked encoding: the same promise over a REST IAM allow policy, whose three (role, member) rows the section unrolls by hand" policy.json
        verify_walkthrough 1 "the end-to-end walkthrough: the terraform binding that grants roles/owner to an outsider" proposal.tf.json
        ;;
    *)
        return 3
        ;;
    esac
    return 0
}

# Steps in <scenario>'s arc, without running any of them (0 = no such arc).
arc_size() {
    local saved_dry=$DRY saved_steps=$STEPS
    DRY=1
    STEPS=0
    if ! arc "$1"; then
        STEPS=0
    fi
    local size=$STEPS
    DRY=$saved_dry
    STEPS=$saved_steps
    printf '%s' "$size"
}

# -- the modes ----------------------------------------------------------------

usage() {
    cat <<'EOF'
usage: ./run_demo.sh <scenario>   run one demo arc end to end
       ./run_demo.sh --list       list the scenarios and what each proposes

Every scenario is one row of README.md's "The scenarios at a glance" table,
and each arc runs the commands that row's README section documents — the
compile-requirements step included — checking each step's exit against the
one the README states. Offline: frozen fixtures, no credentials, no network.
EOF
}

list_scenarios() {
    local rows label prop scen unknown=0 size
    rows="$(readme_scenarios)"
    if [ -z "$rows" ]; then
        printf 'run_demo.sh: no at-a-glance table found in %s\n' "$README" >&2
        return 2
    fi
    printf 'demo scenarios — README.md, "The scenarios at a glance":\n\n'
    while IFS=$'\t' read -r label prop scen _; do
        [ -n "$label" ] || continue
        size="$(arc_size "$label")"
        if [ "$size" = 0 ]; then
            printf '  %-4s (no arc is wired for this scenario)\n' "$label" >&2
            unknown=$((unknown + 1))
            continue
        fi
        printf '  %-4s %d step(s)  %s\n' "$label" "$size" "$prop"
        printf '       %s\n' "$scen"
    done <<EOF
$rows
EOF
    printf '\nrun one with: ./run_demo.sh <scenario>\n'
    if [ "$unknown" != 0 ]; then
        printf 'run_demo.sh: %d scenario(s) in the README have no arc here\n' \
            "$unknown" >&2
        return 1
    fi
    return 0
}

run_scenario() {
    local scenario="$1" rows row label prop scen want=""
    rows="$(readme_scenarios)"
    while IFS=$'\t' read -r label prop scen row; do
        if [ "$label" = "$scenario" ]; then
            want="$row"
            break
        fi
    done <<EOF
$rows
EOF
    if [ -z "$want" ]; then
        printf 'run_demo.sh: no scenario %s in the README table. Try --list.\n' \
            "$scenario" >&2
        return 2
    fi

    TOTAL="$(arc_size "$scenario")"
    if [ "$TOTAL" = 0 ]; then
        printf 'run_demo.sh: no arc is wired for scenario %s\n' "$scenario" >&2
        return 2
    fi

    printf 'demo scenario %s — %s\n' "$scenario" "$scen"
    printf '  proposal      : %s\n' "$prop"
    printf '  README expects: %s\n' "$want"
    printf '  gate command  : %s\n' "${GROUND[*]}"
    if [ -n "$SCRUBBED" ]; then
        printf '  ignoring env  :%s (each arc names its own inputs by flag)\n' \
            "$SCRUBBED"
    fi

    INDEX=0
    DIVERGED=0
    STEPS=0
    arc "$scenario"

    printf '\n'
    if [ "$DIVERGED" = 0 ]; then
        printf 'scenario %s: PASS — %d/%d steps exited as the README documents\n' \
            "$scenario" "$STEPS" "$TOTAL"
        return 0
    fi
    printf 'scenario %s: FAIL — %d of %d steps diverged from the exits the README documents\n' \
        "$scenario" "$DIVERGED" "$TOTAL"
    return 1
}

# No argument is not "run everything" and not a success: a caller whose
# $SCENARIO expanded to nothing should hear about it.
if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

case "$1" in
    --list|-l)
        list_scenarios
        ;;
    --help|-h)
        usage
        ;;
    -*)
        printf 'run_demo.sh: unknown option %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    *)
        run_scenario "$1"
        ;;
esac
