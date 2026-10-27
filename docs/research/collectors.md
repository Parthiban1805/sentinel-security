# Collector research (v0.2 M1), 2026-10-27

Status per item: **confirmed** (read in official docs), **assumed** (not found, must be checked live
before relying on it), or **false** (contradicts the plan).

## Google Cloud
| Item | Status | Detail / source |
|---|---|---|
| Per-key request volume | **confirmed**, with a correction | Metric `serviceruntime.googleapis.com/api/request_count` (DELTA, INT64) on resource `consumed_api`. The metric labels are only `protocol`, `response_code`, `response_code_class`, `grpc_status_code`. `credential_id` is a **resource** label on `consumed_api` ("The client credential ID, such as an API key ID or the OAuth client ID"). Filter with `resource.labels.credential_id`. Sources: [metrics P-Z](https://docs.cloud.google.com/monitoring/api/metrics_gcp_p_z), [monitored resources](https://docs.cloud.google.com/monitoring/api/resources) |
| `credential_id` value format | assumed | Docs give no format. Expected `apikey:<key uid>`; confirm against a live project before matching aliases. |
| Data latency | **confirmed** | "Sampled every 60 seconds. After sampling, data is not visible for up to 1800 seconds." [API monitoring](https://docs.cloud.google.com/apis/docs/monitoring). **Impact:** MTTD for provider-usage signals is at least ~30 minutes, so the <15 min target cannot be met from this source. |
| Caller IP / region | **confirmed absent** | No IP or caller-region label. `location` is the service's location, not the caller's. "Usage from new IP/region" (R1 as written) is not observable here; Sentinel uses volume above baseline and any use of a key that should be dead. |
| API key list | **confirmed** | `GET https://apikeys.googleapis.com/v2/projects/{p}/locations/global/keys`, params `pageSize`, `pageToken`, `showDeleted` (keys deleted in the last 30 days). Scope `cloud-platform.read-only` suffices. Permission `apikeys.keys.list`. "The key string of the API key isn't included in the response." Key fields: `name`, `uid`, `displayName`, `createTime`, `updateTime`, `deleteTime`, `restrictions`, `serviceAccountEmail`. [list](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list), [resource](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys) |
| `getKeyString` | **confirmed exists** | Returns the raw key. Sentinel must never call it (enforced by a path denylist in the HTTP client). |
| Verification from fresh evidence | **confirmed possible** | `list?showDeleted=true` shows `deleteTime` for a deleted key (for 30 days); a key absent from both lists is gone. |
| Gemini / AI Studio keys | assumed | Expected to be ordinary API keys in a Cloud project; confirm live. |
| IAM role names | assumed | `apikeys.keys.list` is confirmed; the role name (`roles/serviceusage.apiKeysViewer`) and Monitoring read role (`roles/monitoring.viewer`) to be confirmed. |
| Cost / billing | deferred | Actual cost needs Billing export to BigQuery. v0.2 uses project request volume as a labelled spend proxy. |

## GitHub (personal account)
| Item | Status | Detail / source |
|---|---|---|
| SSH keys | **confirmed** | `GET /user/keys` (paginated, `per_page` max 100). Fields include `id`, `title`, `created_at`, `verified`, `read_only`, `last_used`. Classic tokens need `read:public_key`; the fine-grained permission is not stated on the page (assumed: "Git SSH keys" read). Sentinel stores only id, title hash and created_at, never the public key body. [docs](https://docs.github.com/en/rest/users/keys) |
| Workflow commits, diff, releases | assumed (standard endpoints) | `GET /repos/{o}/{r}/commits?path=.github/workflows&since=`, `GET /repos/{o}/{r}/commits/{sha}`, `GET /repos/{o}/{r}/releases`. Confirm fine-grained permissions (Contents: read) live. |
| Security log / login history | not found | No REST endpoint for a personal account's security log was found. Treat as unavailable: **R6 cannot see logins for personal accounts**; only `ssh_key_added` is collectable. |

## Consequences for the plan
1. R1 for Google keys becomes: exposed key + request volume above baseline (or any use after it should be dead).
   "New IP/region" stays a hypothesis that needs provider-side investigation.
2. Provider-usage detection latency is about 30 minutes or more (fact from Google docs). The 15-minute MTTD target holds for
   scanner and GitHub signals only.
3. Aliases map `credential_id` values to `cred_ref`. The exact format is checked during the first live run.
