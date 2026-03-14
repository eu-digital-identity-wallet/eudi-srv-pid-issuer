import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import qrcode from 'qrcode-terminal';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';

const PORT = process.env.PORT || 3000;
/** Base URL for the issuer (can be updated to ngrok URL when USE_NGROK=1). */
let baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
const useNgrok = process.env.USE_NGROK === '1' || process.env.USE_NGROK === 'true';

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
    credential_issuer: baseUrl,
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
    credential_issuer: baseUrl,
    authorization_servers: [baseUrl],
    credential_endpoint: `${baseUrl}/credential`,
    nonce_endpoint: `${baseUrl}/nonce`,
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
    issuer: baseUrl,
    token_endpoint: `${baseUrl}/token`,
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
        iss: baseUrl,
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
app.listen(PORT, async () => {
  if (useNgrok) {
    try {
      const ngrok = await import('@ngrok/ngrok');
      const listener = await ngrok.default.forward({
        addr: PORT,
        authtoken_from_env: true,
      });
      baseUrl = listener.url();
      console.log(`ngrok tunnel: ${baseUrl}`);
    } catch (err) {
      console.error('ngrok failed:', err.message);
      console.log(`
  To use ngrok:
  1. Get your token: https://dashboard.ngrok.com/get-started/your-authtoken
  2. Create a file named .env in this folder with one line:
     NGROK_AUTHTOKEN=paste_your_token_here
  3. Run again: npm run start:ngrok
`);
      console.log('Falling back to', baseUrl);
    }
  }

  const offerUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${baseUrl}/credential-offer`)}`;

  console.log(`
╔══════════════════════════════════════════════════════════╗
║         SD-JWT VC Credential Issuer (EUDI Wallet)       ║
╚══════════════════════════════════════════════════════════╝

  Server:  ${baseUrl}
  Offer:   ${offerUrl}

Scan this QR code with your EUDI Wallet app:
`);

  qrcode.generate(offerUrl, { small: true }, (code) => {
    console.log(code);
    if (!useNgrok) {
      console.log(`
TIP: To expose this server to your phone via ngrok, restart with:
     USE_NGROK=1 npm start
     (Requires NGROK_AUTHTOKEN from https://dashboard.ngrok.com/get-started/your-authtoken)
`);
    }
  });
});
