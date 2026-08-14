# User Guide

## 1. Create an account

Open the app (`http://localhost:3000` by default) — you're redirected to
**Log in**. Follow the "Register" link, enter an email and an 8+ character
password, and submit. You're logged in immediately and land on the
**Policies** page.

## 2. Upload a policy

On the Policies page, fill in the upload form:
- **Policy name** — any label you'll recognize later.
- **Source type** — `AWS Security Group` for a `describe-security-groups`
  JSON export, `IAM Policy` for a simplified IAM policy document, or
  `Firewall` for the generic YAML/JSON rule format (also used for
  GCP-style exports).
- **File** — the export file itself.

Submit, and the parsed policy appears in the table below with its rule
count. If the file is malformed, too large (10MB default limit), or uses
an unsupported source type, an error message explains why — nothing is
saved.

## 3. Run an analysis

Click a policy's name in the table to trigger analysis. This calls the
Python analysis engine, which checks every rule for overly permissive
access, conflicts with other rules (shadowing, redundancy, contradiction),
staleness/orphaned status, and violations of the CIS, HIPAA, and PCI-DSS
compliance rulesets — then redirects you to that analysis's dashboard.

## 4. Read the dashboard

- **Risk gauge** — the overall 0-100 score plus its four components
  (permissiveness, exposure, compliance violations, unused).
- **Compliance chart** — a bar chart of compliance-violation findings by
  severity.
- **Risk matrix** — a scatter plot of each finding's exposure (does it
  touch a critical port like 22, 3389, or 5432) against its severity.
- **Network diagram** — an interactive graph of the policy's traffic:
  nodes are source/destination endpoints, edges are rules, red edges have
  findings attached. Check "Critical only" to dim everything but
  critical-severity edges, click an edge to open its rule detail panel, or
  use "Export PNG" to save the current layout as an image.
- **Findings table** — every finding, filterable by severity and type via
  the controls above it, sortable by clicking the Severity or Type column
  header. Click a row to open that rule's detail panel (protocol,
  direction, action, ports, source/destination, description).

## 5. Export a report

From the API directly (a dedicated UI export button is a natural next
addition, but isn't wired up yet): `GET /api/analyses/:id/report` with
your bearer token returns a PDF containing the risk score breakdown and
every finding with its recommendation.

## 6. Delete a policy

Click "Delete" next to a policy in the table. This also removes it from
your list immediately; its past analyses remain queryable by ID but are no
longer reachable through the policy list.
