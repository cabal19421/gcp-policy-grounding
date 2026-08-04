# acme-prod platform

Runbooks, terraform and policy for the acme-prod project.

## Pipelines

### events-etl (new)

Hourly BigQuery load from the `events` Pub/Sub topic, run by
`etl-runner@acme-prod`. Access is granted in `pipeline/iam.policy.json`;
the network narrowing for the ingest subnet is in
`pipeline/firewall.tfplan.json`.

On-call: `platform-sre@acme.example`.
