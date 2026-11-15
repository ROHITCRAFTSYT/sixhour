# Security policy

## Reporting a vulnerability

Please report security problems privately through
[GitHub security advisories](https://github.com/ROHITCRAFTSYT/sixhour/security/advisories/new).
Do not open a public issue for a security bug.

You can expect a first reply within 3 working days. Please include steps to reproduce and,
if you can, the request ID from the `X-Request-ID` response header.

## Scope

- The hosted desk at https://sixhour-ashen.vercel.app
- The code in this repository

Things of particular interest: anything that makes the server keep or log pasted content,
a way for unmasked personal identifiers to reach the model, a bypass of the guardrails in
`pipeline.py` / `model.py`, script injection through log content or model output, and
bypasses of the rate or size limits.

## How data is handled

See [the security page](https://sixhour-ashen.vercel.app/security).
