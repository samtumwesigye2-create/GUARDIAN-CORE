# UNG GUARDIAN — foundation

This is the executable foundation generated from the supplied Guardian ecosystem schema.
It implements registration, heartbeat ingestion, findings, fix proposals, action logging,
and the mandatory approval gate for finance/payroll/tax/vault/code/infrastructure categories.
It does not auto-apply production code or high-risk changes.

Required environment variables: `DATABASE_URL`, `GUARDIAN_SERVICE_TOKEN`.
