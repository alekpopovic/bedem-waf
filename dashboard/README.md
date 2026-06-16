# BedemWAF Dashboard

The dashboard is the Next.js and TypeScript admin UI for BedemWAF. The MVP can:

- Sign in with a development admin API key
- View security overview cards
- List apps and active policy versions
- Create apps
- View app details
- Edit and publish policy JSON drafts
- Search WAF events
- View full event details
- Show an API keys placeholder

## Configuration

Set the Control API URL exposed to the browser:

```bash
export NEXT_PUBLIC_CONTROL_API_URL="http://localhost:8081"
```

The admin API key is entered on `/login` and stored in browser `localStorage`.
This is development-only behavior. TODO: replace with proper session
authentication before production use.

## Run

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Open:

```text
http://localhost:3000/login
```

## Control API Compatibility

The UI uses the documented Control API endpoints:

- `GET /v1/tenants`
- `GET /v1/apps`
- `POST /v1/apps`
- `GET /v1/apps/{app_id}`
- `GET /v1/apps/{app_id}/policies`
- `POST /v1/apps/{app_id}/policies`
- `GET /v1/apps/{app_id}/active-policy`
- `GET /v1/policies/{policy_id}`
- `PATCH /v1/policies/{policy_id}`
- `POST /v1/policies/{policy_id}/publish`
- `GET /v1/events`
- `GET /v1/events/{request_id}`

## Quality

```bash
npm run typecheck
npm run build
```

No secrets are committed to the repository. Use local `.env` files for
development values.
