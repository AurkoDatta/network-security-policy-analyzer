# API Documentation

Base URL (local dev): `http://localhost:5000`. All `/api/*` routes except
`/api/auth/register` and `/api/auth/login` require an `Authorization: Bearer
<token>` header. Tokens are issued by register/login and expire after 24
hours; refresh with `POST /api/auth/refresh`.

## Authentication

### `POST /api/auth/register`
Body: `{ "email": string, "password": string (min 8 chars), "name"?: string }`
Response: `201 { "token": string }`. `409` if the email is already registered.

### `POST /api/auth/login`
Body: `{ "email": string, "password": string }`
Response: `200 { "token": string }`. `401` on invalid credentials.

### `POST /api/auth/refresh`
No body. Requires a valid existing token. Response: `200 { "token": string }`.

## Policies

All policy routes require auth and only ever operate on the requesting
user's own policies — cross-user access returns `403`, not `404`, so
resource existence is never leaked to non-owners.

### `POST /api/policies/upload`
`multipart/form-data`: `name` (string), `source_type` (`aws` | `firewall` |
`iam`), `file` (the policy export). `aws` maps to the analyzer's
`security_group` parser, `iam` maps to `iam_policy`, `firewall` is used
as-is — this generic parser also covers GCP-style firewall exports well
enough that no separate GCP parser exists.
Response: `201` with the created `Policy` document (including
`normalized_rules`). `400` on missing fields or a file the analyzer can't
parse. `413` if the file exceeds `MAX_FILE_SIZE` (default 10MB).

### `GET /api/policies`
Response: `200` — array of the requesting user's `Policy` documents, newest
first.

### `GET /api/policies/:id`
Response: `200` with the `Policy`. `404` if it doesn't exist, `403` if it
belongs to another user.

### `DELETE /api/policies/:id`
Response: `204`. Same `404`/`403` rules as above.

### `POST /api/policies/:id/analyze`
Triggers analysis of the policy's `normalized_rules` against the CIS,
HIPAA, and PCI-DSS compliance rulesets, and stores the result. Emits
WebSocket progress events (see below) while running. Repeated analyze
calls for a policy whose content hasn't changed reuse the cached analyzer
result rather than recomputing it. Response: `201` with the created
`Analysis` document. `502` if the analyzer service call fails.

## Analyses

### `GET /api/analyses/:id`
Response: `200` with the `Analysis` (`risk_score`, `findings`,
`generated_at`). `403`/`404` follow the same ownership rules as policies,
resolved via the analysis's parent policy.

### `GET /api/analyses/:id/report`
Response: `200`, `Content-Type: application/pdf` — a generated PDF report
containing the risk score breakdown and every finding with its
recommendation.

## Real-time analysis progress

Connect a Socket.io client to the API's base URL with `path: '/ws/analyze'`,
then emit `join` with the policy ID to subscribe to that policy's progress
room. The server emits `progress` events shaped `{ stage: string, percent:
number }` as an analysis proceeds (`sending_to_analyzer` → 25,
`scoring_complete` → 75, `complete` → 100, or `failed` → 100 on error).

## Compliance rules

`GET /api/compliance-rules` is mounted but not yet implemented (`501`) —
the three bundled frameworks (CIS, HIPAA, PCI-DSS) and custom ruleset
loading already exist inside the analyzer service (`src/compliance/`) and
are used directly by the analyze endpoint; exposing them as their own
CRUD API was out of scope for this project's phases.

## Errors

Every error response is `{ "error": string }` (validation errors from
`POST /api/auth/register` additionally include a `details` field with
per-field messages). `500` responses are logged server-side as structured
JSON (`timestamp`, `method`, `path`, `message`, `stack`) and never leak
internal details to the client.
