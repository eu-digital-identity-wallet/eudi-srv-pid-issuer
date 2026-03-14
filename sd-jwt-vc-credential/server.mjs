import express from 'express';
import crypto from 'crypto';
import qrcode from 'qrcode-terminal';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── Issuer key pair (generated fresh on each startup) ──────────────────────
const { publicKey: issuerPub, privateKey: issuerPriv } = await ES256.generateKeyPair();
const signer = await ES256.getSigner(issuerPriv);
const verifier = await ES256.getVerifier(issuerPub);

const sdjwt = new SDJwtVcInstance({
  signer,
  signAlg: 'ES256',
  verifier,
  hasher: digest,
  hashAlg: 'sha-256',
  saltGenerator: generateSalt,
});

// ── In-memory stores ───────────────────────────────────────────────────────
const PRE_AUTH_CODE = crypto.randomUUID();
const validTokens = new Set();

// ── Express app ────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. Credential Offer (wallet fetches this from the QR link)
app.get('/credential-offer', (_req, res) => {
  res.json({
    credential_issuer: BASE_URL,
    credential_configuration_ids: ['SimpleCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': PRE_AUTH_CODE,
      },
    },
  });
});

// 2. Credential Issuer Metadata
app.get('/.well-known/openid-credential-issuer', (_req, res) => {
  res.json({
    credential_issuer: BASE_URL,
    authorization_servers: [BASE_URL],
    credential_endpoint: `${BASE_URL}/credential`,
    nonce_endpoint: `${BASE_URL}/nonce`,
    display: [{ name: 'Simple SD-JWT VC Issuer', locale: 'en' }],
    credential_configurations_supported: {
      SimpleCredential: {
        format: 'vc+sd-jwt',
        vct: 'urn:eu.europa.ec.eudi:simple:credential:1',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        display: [
          {
            name: 'Simple Credential',
            locale: 'en',
            description: 'A simple identity credential',
          },
        ],
        claims: {
          family_name: { display: [{ name: 'Family Name', locale: 'en' }] },
          given_name: { display: [{ name: 'Given Name', locale: 'en' }] },
          email: { display: [{ name: 'Email', locale: 'en' }] },
          birthdate: { display: [{ name: 'Date of Birth', locale: 'en' }] },
        },
      },
    },
  });
});

// 3. Authorization Server Metadata
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: BASE_URL,
    token_endpoint: `${BASE_URL}/token`,
    response_types_supported: [],
    grant_types_supported: [
      'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    ],
    'pre-authorized_grant_anonymous_access_supported': true,
  });
});

// 4. Token Endpoint (pre-authorized code → access token + c_nonce)
app.post('/token', (req, res) => {
  const code =
    req.body['pre-authorized_code'] || req.body['pre_authorized_code'];

  if (code !== PRE_AUTH_CODE) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const accessToken = crypto.randomUUID();
  validTokens.add(accessToken);

  const cNonce = crypto.randomUUID();

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86400,
    c_nonce: cNonce,
    c_nonce_expires_in: 86400,
  });
});

// 5. Nonce Endpoint
app.post('/nonce', (_req, res) => {
  res.json({
    c_nonce: crypto.randomUUID(),
    c_nonce_expires_in: 86400,
  });
});

// 6. Credential Endpoint — the main event
app.post('/credential', async (req, res) => {
  // Check bearer token
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!validTokens.has(token)) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  // Extract holder public key from the proof JWT header
  let holderJwk;
  try {
    const proofJwt = req.body.proof?.jwt || req.body.proofs?.jwt?.[0];
    const headerB64 = proofJwt.split('.')[0];
    const header = JSON.parse(
      Buffer.from(headerB64, 'base64url').toString('utf8'),
    );
    holderJwk = header.jwk;
    if (!holderJwk) throw new Error('no jwk in proof header');
  } catch {
    return res.status(400).json({ error: 'invalid_proof' });
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const credential = await sdjwt.issue(
      {
        iss: BASE_URL,
        iat: now,
        exp: now + 30 * 24 * 60 * 60,
        vct: 'urn:eu.europa.ec.eudi:simple:credential:1',
        cnf: { jwk: holderJwk },
        family_name: 'Doe',
        given_name: 'John',
        email: 'john.doe@example.com',
        birthdate: '1990-01-15',
      },
      {
        _sd: ['family_name', 'given_name', 'email', 'birthdate'],
      },
      {
        header: { typ: 'vc+sd-jwt' },
      },
    );

    console.log('\n--- Credential issued! ---');

    res.json({
      credential,
      c_nonce: crypto.randomUUID(),
      c_nonce_expires_in: 86400,
    });
  } catch (err) {
    console.error('Issuance error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const offerUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${BASE_URL}/credential-offer`)}`;

  console.log(`
╔══════════════════════════════════════════════════════════╗
║         SD-JWT VC Credential Issuer (EUDI Wallet)       ║
╚══════════════════════════════════════════════════════════╝

  Server:  ${BASE_URL}
  Offer:   ${offerUrl}

Scan this QR code with your EUDI Wallet app:
`);

  qrcode.generate(offerUrl, { small: true }, (code) => {
    console.log(code);
    console.log(`
TIP: Your phone must be able to reach ${BASE_URL}
     If running locally, set BASE_URL to your machine's IP or use ngrok:
       npx ngrok http ${PORT}
     Then restart with:
       BASE_URL=https://<your-ngrok-url> npm start
`);
  });
});
