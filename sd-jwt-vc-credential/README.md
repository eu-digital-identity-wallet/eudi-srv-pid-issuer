# SD-JWT VC Credential Issuer

Minimal OpenID4VCI issuer that generates an SD-JWT VC credential you can scan into your EUDI Wallet.

## Quick Start

```bash
cd sd-jwt-vc-credential
npm install
npm start
```

Scan the QR code that appears in your terminal with the EUDI Wallet app.

## Making it reachable from your phone

Your phone needs to reach the server. Options:

**Option A — Same network (use your machine's local IP):**
```bash
BASE_URL=http://192.168.1.42:3000 npm start
```

**Option B — ngrok tunnel:**
```bash
npx ngrok http 3000
# copy the https URL, then:
BASE_URL=https://xxxx.ngrok-free.app npm start
```

## What it does

1. Starts an HTTP server with all the OpenID4VCI endpoints
2. Shows a `openid-credential-offer://` QR code
3. Your EUDI Wallet scans it → fetches issuer metadata → gets a token → requests the credential
4. Server issues an SD-JWT VC with these selectively-disclosable claims:
   - `family_name` → "Doe"
   - `given_name` → "John"
   - `email` → "john.doe@example.com"
   - `birthdate` → "1990-01-15"

## Configuration

| Env var    | Default                  | Description            |
|------------|--------------------------|------------------------|
| `PORT`     | `3000`                   | Server port            |
| `BASE_URL` | `http://localhost:$PORT`  | Public URL of server   |
