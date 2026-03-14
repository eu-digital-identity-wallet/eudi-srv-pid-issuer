import express from 'express';
import crypto from 'crypto';
import qrcode from 'qrcode-terminal';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── Issuer key pair (generated fresh on each startup) ──────────────────────
const ISSUER_KID = `issuer-key-${crypto.randomUUID().slice(0, 8)}`;
const { publicKey: issuerPub, privateKey: issuerPriv } =
  await ES256.generateKeyPair();
const signer = await ES256.getSigner(issuerPriv);
const verifier = await ES256.getVerifier(issuerPub);

const issuerJwk = { ...issuerPub, kid: ISSUER_KID, use: 'sig', alg: 'ES256' };
const jwks = { keys: [issuerJwk] };

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

// ── Credential configurations ──────────────────────────────────────────────
const VCT = 'urn:eu.europa.ec.eudi:simple:credential:1';

const CLAIMS_METADATA = {
  family_name: { display: [{ name: 'Family Name', locale: 'en' }] },
  given_name: { display: [{ name: 'Given Name', locale: 'en' }] },
  email: { display: [{ name: 'Email', locale: 'en' }] },
  birthdate: { display: [{ name: 'Date of Birth', locale: 'en' }] },
};

// Map config id → format typ header
const CREDENTIAL_CONFIGS = {
  SimpleCredential: { format: 'vc+sd-jwt', typ: 'vc+sd-jwt' },
  SimpleCredentialDC: { format: 'dc+sd-jwt', typ: 'dc+sd-jwt' },
};

function credentialConfigMetadata(format) {
  return {
    format,
    vct: VCT,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['ES256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256'] },
    },
    display: [
      {
        name:
          format === 'dc+sd-jwt'
            ? 'Simple Credential (DC)'
            : 'Simple Credential',
        locale: 'en',
        description: 'A simple identity credential',
      },
    ],
    claims: CLAIMS_METADATA,
  };
}

// ── Express app ────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// ── 1. Credential Offer ────────────────────────────────────────────────────
app.get('/credential-offer', (_req, res) => {
  res.json({
    credential_issuer: BASE_URL,
    credential_configuration_ids: ['SimpleCredentialDC', 'SimpleCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': PRE_AUTH_CODE,
      },
    },
  });
});

// ── 2. Credential Issuer Metadata ──────────────────────────────────────────
app.get('/.well-known/openid-credential-issuer', (_req, res) => {
  res.json({
    credential_issuer: BASE_URL,
    authorization_servers: [BASE_URL],
    credential_endpoint: `${BASE_URL}/credential`,
    nonce_endpoint: `${BASE_URL}/nonce`,
    jwks_uri: `${BASE_URL}/jwks`,
    display: [{ name: 'Simple SD-JWT VC Issuer', locale: 'en' }],
    credential_configurations_supported: {
      SimpleCredentialDC: credentialConfigMetadata('dc+sd-jwt'),
      SimpleCredential: credentialConfigMetadata('vc+sd-jwt'),
    },
  });
});

// ── 3. JWKS ────────────────────────────────────────────────────────────────
app.get('/jwks', (_req, res) => res.json(jwks));

// ── 4. JWT VC Issuer Metadata ──────────────────────────────────────────────
app.get('/.well-known/jwt-vc-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks` });
});
app.get('/.well-known/jwt-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks` });
});

// ── 5. Authorization Server Metadata ───────────────────────────────────────
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

// ── 6. Token Endpoint ──────────────────────────────────────────────────────
app.post('/token', (req, res) => {
  const code =
    req.body['pre-authorized_code'] || req.body['pre_authorized_code'];

  if (code !== PRE_AUTH_CODE) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const accessToken = crypto.randomUUID();
  validTokens.add(accessToken);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86400,
  });
});

// ── 7. Nonce Endpoint ──────────────────────────────────────────────────────
app.post('/nonce', (_req, res) => {
  const nonce = crypto.randomUUID();
  console.log(`  -> issued c_nonce: ${nonce.slice(0, 8)}...`);
  res.json({ c_nonce: nonce });
});

// ── 8. Credential Endpoint ─────────────────────────────────────────────────
app.post('/credential', async (req, res) => {
  console.log('  -> body:', JSON.stringify(req.body, null, 2));

  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!validTokens.has(token)) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  // Extract holder public key from proof JWT header
  // EUDI wallet sends: { proofs: { jwt: ["eyJ..."] } }
  // Other wallets may send: { proof: { proof_type: "jwt", jwt: "eyJ..." } }
  let holderJwk;
  try {
    const proofJwt =
      req.body.proofs?.jwt?.[0] ||
      req.body.proof?.jwt;
    if (!proofJwt) throw new Error('no proof jwt found');
    const headerB64 = proofJwt.split('.')[0];
    const header = JSON.parse(
      Buffer.from(headerB64, 'base64url').toString('utf8'),
    );
    holderJwk = header.jwk;
    if (!holderJwk) throw new Error('no jwk in proof header');
  } catch (e) {
    console.error('  -> proof extraction failed:', e.message);
    return res.status(400).json({ error: 'invalid_proof' });
  }

  // Determine typ from credential_configuration_id, format, or credential_identifier
  const configId = req.body.credential_configuration_id;
  const requestedFormat = req.body.format;
  let typ = 'dc+sd-jwt'; // default to dc+sd-jwt (EUDI wallet preference)

  if (configId && CREDENTIAL_CONFIGS[configId]) {
    typ = CREDENTIAL_CONFIGS[configId].typ;
  } else if (requestedFormat === 'vc+sd-jwt') {
    typ = 'vc+sd-jwt';
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const credential = await sdjwt.issue(
      {
        iss: BASE_URL,
        iat: now,
        exp: now + 30 * 24 * 60 * 60,
        vct: VCT,
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
        header: { typ, kid: ISSUER_KID },
      },
    );

    console.log(`  -> credential issued (${typ})`);

    // Response format per OpenID4VCI draft 15+:
    // { "credentials": [ { "credential": "..." } ] }
    res.json({
      credentials: [{ credential }],
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

  Server:     ${BASE_URL}
  JWKS:       ${BASE_URL}/jwks
  Formats:    dc+sd-jwt, vc+sd-jwt
  Issuer kid: ${ISSUER_KID}
  Offer:      ${offerUrl}

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
