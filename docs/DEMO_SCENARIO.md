# Demo scenario: repeated failed logins

## Objective
Show the end-to-end path from synthetic event ingestion to alert triage and incident creation.

## Steps
1. Start the application locally.
2. Click **Load demo data**.
3. Confirm the dashboard counters increase.
4. Locate the high-severity "Possible brute-force activity" alert for `198.51.100.24`.
5. Click **Investigate**.
6. Confirm the alert status changes and an incident appears in `/api/incidents`.

## Evidence to capture
- Dashboard with counters and alerts
- OpenAPI page showing event ingestion endpoint
- Test output from `pytest -q`
- Incident record returned by `/api/incidents`

## Interview explanation
ThreatLens demonstrates a defensive event-processing workflow using synthetic inputs. Its rules are intentionally simple and explainable. Next steps include robust time-window aggregation, labelled test data, false-positive evaluation, authentication and authorization, and integration with a real log source in an authorized lab.
