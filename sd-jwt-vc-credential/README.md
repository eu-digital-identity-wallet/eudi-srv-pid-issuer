# SD-JWT VC Credential Issuer

Minimal OpenID4VCI issuer that generates SD-JWT VC credentials you can scan into your EUDI Wallet.

## Quick Start

```bash
cd sd-jwt-vc-credential
npm install
```

### For EUDI Wallet (requires HTTPS)

The EUDI Wallet requires HTTPS. Use ngrok to create a tunnel:

```bash
npx ngrok http 3000
```

Copy the `https://` URL ngrok gives you, then:

```bash
BASE_URL=https://xxxx.ngrok-free.app npm start
```

Scan the QR code with your EUDI Wallet.

### For other wallets (HTTP is fine)

```bash
npm start
```

Or with your machine's LAN IP:

```bash
BASE_URL=http://192.168.1.42:3000 npm start
```

## What happens

1. Server starts with all OpenID4VCI endpoints
2. QR code appears in your terminal (`openid-credential-offer://...`)
3. Wallet scans it → fetches metadata → gets token → requests credential
4. Server issues an SD-JWT VC with selectively-disclosable claims:
   - `family_name` → "Doe"
   - `given_name` → "John"
   - `email` → "john.doe@example.com"
   - `birthdate` → "1990-01-15"

## Formats

| Config ID            | Format       | Wallet support          |
|----------------------|--------------|-------------------------|
| `SimpleCredentialDC` | `dc+sd-jwt`  | EUDI Wallet, others     |
| `SimpleCredential`   | `vc+sd-jwt`  | Non-EUDI wallets        |

## Endpoints

| Endpoint                                     | Method | Description                  |
|----------------------------------------------|--------|------------------------------|
| `/credential-offer`                          | GET    | Credential offer             |
| `/.well-known/openid-credential-issuer`      | GET    | Issuer metadata              |
| `/.well-known/oauth-authorization-server`    | GET    | Auth server metadata         |
| `/.well-known/openid-configuration`          | GET    | Auth server metadata (alias) |
| `/.well-known/jwt-vc-issuer`                 | GET    | JWT VC issuer metadata       |
| `/jwks`                                      | GET    | Issuer public keys           |
| `/token`                                     | POST   | Token (pre-auth code)        |
| `/nonce`                                     | POST   | Nonce for proof JWT          |
| `/credential`                                | POST   | Credential issuance          |

## Configuration

| Env var    | Default                  | Description            |
|------------|--------------------------|------------------------|
| `PORT`     | `3000`                   | Server port            |
| `BASE_URL` | `http://localhost:$PORT`  | Public URL (use HTTPS for EUDI Wallet) |
