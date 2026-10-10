# SecureTrap Dashboard

A read-only web dashboard for the SecureTrap API. Phase 8.1 is the **foundation**:
the application shell, navigation, API client, configuration, and an **Overview**
page built from `GET /health` and `GET /api/v1/alerts/summary`.

The alerts table, alert detail view and charts come in later phases. The code is
already organised so they can be added without reworking the shell (see
[Structure](#structure)).

## Requirements

- Node.js `^20.19.0`, `^22.13.0` or `>=24.0.0` (enforced by `engines`; Vite 7 needs it)
- A running SecureTrap API for real data (the tests do not need one)

## Quick start

```bash
cd dashboard
npm ci            # installs the exact versions pinned in package-lock.json
npm run dev       # http://localhost:3000
```

With the API running locally (from the repository root):

```bash
uvicorn api.app:create_app --factory --port 8000
```

`npm run dev` loads `.env.development`, which points the dashboard at
`http://localhost:8000`.

The dev server and `npm run preview` both use **port 3000 with `strictPort`**.
That is the one origin the API allows by default (`SECURETRAP_CORS_ORIGINS`
defaults to `http://localhost:3000`). If port 3000 is busy, the server stops
instead of silently moving to another port, because a different port would be
blocked by the browser's CORS check.

## Scripts

| Command             | What it does                                              |
| ------------------- | --------------------------------------------------------- |
| `npm run dev`       | Vite dev server on port 3000                              |
| `npm run build`     | Type-check, then production build into `dist/`            |
| `npm run preview`   | Serve the production build on port 3000                   |
| `npm run typecheck` | `tsc --noEmit`                                            |
| `npm run lint`      | ESLint (includes the HTML-injection ban, see Security)    |
| `npm test`          | Run the Vitest suite once                                 |
| `npm run test:watch`| Vitest in watch mode                                      |

## Configuring the API URL

The only setting is `VITE_API_BASE_URL`. There is **no hard-coded production API
URL** anywhere in the source.

| Value                             | Meaning                                                      |
| --------------------------------- | ------------------------------------------------------------ |
| unset or empty                    | Same origin as the dashboard (e.g. behind a reverse proxy)   |
| `http://host:8000`                | Absolute http(s) URL; the API must allow this origin via CORS |
| `/securetrap-api`                 | Same origin, with a path prefix                              |

Anything else (`localhost:8000` with no scheme, `ftp://…`, `//host`, URLs with
credentials, a query string or a fragment, whitespace inside) is rejected and
the dashboard shows a configuration error page instead of guessing. The rejected
value is deliberately not echoed back.

Vite bakes the value in **at build time**:

- `npm run dev` reads `.env.development` (`http://localhost:8000`).
- `npm run build` does **not** read `.env.development`. Set the variable for the
  build (`VITE_API_BASE_URL=https://api.example.org npm run build`) or leave it
  unset to use the same origin.
- Put personal overrides in `.env.local` (git-ignored).

See `.env.example` for the annotated template.

## What the Overview shows, and what it does not

All figures come from `GET /api/v1/alerts/summary` and describe **persisted
alert records only**:

| Card                                  | Source field    | Meaning                                                              |
| ------------------------------------- | --------------- | -------------------------------------------------------------------- |
| Persisted alerts                      | `total_alerts`  | Alert records currently stored                                       |
| Persisted anomalies                   | `anomaly_count` | Stored records flagged as statistical outliers                       |
| Persisted non-anomalous records       | `normal_count`  | Stored records *not* flagged. **Not** all normal predictions the model made |
| Anomaly share of persisted records    | `anomaly_rate`  | A 0.0–1.0 ratio shown as a percentage, over persisted records only   |

Wording rules enforced in code and tests:

- An *anomaly* is an IsolationForest statistical outlier. It is **not** a
  confirmed attack, and scores are **not** probabilities or confidence values.
- The live pipeline persists only anomalous results, so `normal_count` is
  normally `0` and the share is normally `100%`. The page says so instead of
  presenting 100% as an alarming finding.
- `GET /health` is liveness only. The header pill therefore says
  **"API reachable"** and states that this does not verify the database, the
  detection service or the honeypot. The dashboard never says "healthy" or
  "operational".
- An empty store is reported as *"No alerts persisted yet"* with a note that the
  dashboard cannot distinguish "nothing flagged" from "detector not running",
  because no endpoint reports detector activity.

### States

The Overview has explicit, separately tested states:

| State       | When                                                                 |
| ----------- | -------------------------------------------------------------------- |
| Loading     | First request in flight (skeleton cards, announced to screen readers) |
| Ready       | Summary loaded and `total_alerts > 0`                                |
| Empty       | Summary loaded and `total_alerts == 0`                               |
| Unavailable | Network failure or timeout (also what a CORS block looks like)       |
| Error       | The API answered with an HTTP error, or an unexpected response body  |
| Stale       | A refresh failed but earlier data exists: old figures stay, with a notice |

Data refreshes every 30 seconds while the tab is visible, and on demand with the
**Refresh** button. Requests time out after 10 seconds.

## Security notes

- Honeypot-derived text (commands, IPs, status strings) is only ever rendered as
  React text. ESLint bans `dangerouslySetInnerHTML`, `innerHTML` and
  `insertAdjacentHTML` in `src/`, and a test scans the source for them.
- Every API response is validated at runtime before use. Count maps are built
  with `Object.fromEntries`, so hostile keys such as `__proto__` stay inert data.
- Requests use `credentials: 'omit'`. The dashboard has no authentication
  because the API has none yet; this is a read-only view for a trusted network,
  not something to expose publicly as-is.
- Nothing is written to `localStorage`, `sessionStorage` or cookies.
- When deploying, serve the built files with a Content-Security-Policy that
  limits `connect-src` to the API origin. The bundle uses no inline scripts or
  external fonts.

## Structure

```
dashboard/
├── index.html
├── vite.config.ts          # dev/preview port 3000, Vitest config
├── eslint.config.js
├── public/favicon.svg
└── src/
    ├── main.tsx            # providers (React Query, Router)
    ├── App.tsx             # routes; config error page
    ├── config.ts           # VITE_API_BASE_URL resolution + validation
    ├── copy.ts             # ALL semantic wording lives here (and is tested)
    ├── api/                # client (timeouts, errors), runtime validators, endpoints
    ├── hooks/              # useHealth, useAlertSummary (React Query)
    ├── pages/              # OverviewPage + its state machine, NotFound, ConfigError
    ├── components/         # SummaryCards, StatePanel, ApiStatus, ... and layout/
    ├── utils/format.ts     # number / percent / time formatting
    ├── styles/global.css   # design tokens, dark-first with light theme
    └── test/               # MSW server, fixtures, render helpers
```

Where later phases plug in:

- **Alerts table / detail** — add a route in `App.tsx`, enable the `Alerts` item in
  `components/layout/NavBar.tsx` (currently shown as "Soon" and not focusable),
  and add endpoints in `api/endpoints.ts` with a validator in `api/validators.ts`.
- **New wording** — add it to `copy.ts`. `copy.test.ts` and `source-safety.test.ts`
  fail if banned claims ("attack" outside a negation, "probability"/"confidence"
  outside the disclaimer, "healthy", "operational", …) appear anywhere else.

## Testing

```bash
npm test
```

Vitest + jsdom + React Testing Library + MSW. MSW runs with
`onUnhandledRequest: 'error'`, so a test that makes an unmocked request fails
instead of reaching the network. Tests use the fake origin `http://api.test`,
set in `vite.config.ts`, so they never depend on a local `.env` file.

## Known limits (by design, for this phase)

- No alerts table, detail page, charts, filtering or pagination. The API's list
  endpoint only supports `limit`.
- No real-time push; the Overview polls.
- No authentication, reporting or Docker setup.
- Built assets are referenced from `/`. Serving the dashboard from a sub-path
  needs Vite's `base` option set at build time; this is not configured yet.
