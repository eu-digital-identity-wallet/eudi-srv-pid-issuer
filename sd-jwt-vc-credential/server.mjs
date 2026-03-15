import express from 'express';
import crypto from 'crypto';
import qrcode from 'qrcode-terminal';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── Issuer key pair ────────────────────────────────────────────────────────
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

// ── State ──────────────────────────────────────────────────────────────────
const PRE_AUTH_CODE = crypto.randomUUID();
const validTokens = new Set();

// ── Credential configs ─────────────────────────────────────────────────────
const VCT = 'urn:eu.europa.ec.eudi:simple:credential:1';

// EUDI wallet expects claims as a list of {path, display} objects
// nested under credential_metadata
const CREDENTIAL_METADATA = {
  display: [
    {
      name: 'Simple Credential',
      locale: 'en',
      description: 'A simple identity credential',
    },
  ],
  claims: [
    {
      path: ['family_name'],
      mandatory: true,
      display: [{ name: 'Family Name', locale: 'en' }],
    },
    {
      path: ['given_name'],
      mandatory: true,
      display: [{ name: 'Given Name', locale: 'en' }],
    },
    {
      path: ['email'],
      mandatory: true,
      display: [{ name: 'Email', locale: 'en' }],
    },
    {
      path: ['birthdate'],
      mandatory: true,
      display: [{ name: 'Date of Birth', locale: 'en' }],
    },
  ],
};

const CREDENTIAL_CONFIGS = {
  SimpleCredentialDC: { format: 'dc+sd-jwt', typ: 'dc+sd-jwt' },
  SimpleCredential: { format: 'vc+sd-jwt', typ: 'vc+sd-jwt' },
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
    credential_metadata: CREDENTIAL_METADATA,
  };
}

// ── Express app ────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(`  ${req.method} ${req.path}`);
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
    jwks,
    credential_configurations_supported: {
      SimpleCredentialDC: credentialConfigMetadata('dc+sd-jwt'),
      SimpleCredential: credentialConfigMetadata('vc+sd-jwt'),
    },
  });
});

// ── 3. JWKS ────────────────────────────────────────────────────────────────
app.get('/jwks', (_req, res) => res.json(jwks));

// ── 4. JWT VC / Issuer Metadata ────────────────────────────────────────────
app.get('/.well-known/jwt-vc-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks`, jwks });
});
app.get('/.well-known/jwt-issuer', (_req, res) => {
  res.json({ issuer: BASE_URL, jwks_uri: `${BASE_URL}/jwks`, jwks });
});

// ── 5. Authorization Server Metadata ───────────────────────────────────────
// Serve at both paths — wallets may try either one
function authServerMetadata() {
  return {
    issuer: BASE_URL,
    token_endpoint: `${BASE_URL}/token`,
    response_types_supported: [],
    grant_types_supported: [
      'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    ],
    'pre-authorized_grant_anonymous_access_supported': true,
    token_endpoint_auth_methods_supported: ['none'],
  };
}
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json(authServerMetadata());
});
app.get('/.well-known/openid-configuration', (_req, res) => {
  res.json(authServerMetadata());
});

// ── 6. Token Endpoint ──────────────────────────────────────────────────────
app.post('/token', (req, res) => {
  const code =
    req.body['pre-authorized_code'] ||
    req.body['pre_authorized_code'] ||
    req.query['pre-authorized_code'];

  if (code !== PRE_AUTH_CODE) {
    console.log('  -> token rejected: bad pre-auth code');
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const accessToken = crypto.randomUUID();
  validTokens.add(accessToken);

  console.log(`  -> token issued: ${accessToken.slice(0, 8)}...`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86400,
  });
});

// ── 7. Nonce Endpoint ──────────────────────────────────────────────────────
app.post('/nonce', (_req, res) => {
  const nonce = crypto.randomUUID();
  console.log(`  -> c_nonce: ${nonce.slice(0, 8)}...`);
  res.json({ c_nonce: nonce });
});

// ── 8. Credential Endpoint ─────────────────────────────────────────────────
app.post('/credential', async (req, res) => {
  console.log('  -> body:', JSON.stringify(req.body));

  // Accept both Bearer and DPoP token formats
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^(Bearer|DPoP)\s+/i, '');
  if (!validTokens.has(token)) {
    console.log('  -> rejected: invalid token');
    return res.status(401).json({ error: 'invalid_token' });
  }

  // Extract holder key binding from proof JWT header.
  // Wallets send the holder key in one of two ways:
  //   - jwk: the public key is embedded directly in the header
  //   - kid: a DID or key identifier referencing the holder's key
  // EUDI wallet sends: { proofs: { jwt: ["eyJ..."] } }
  // Other wallets send: { proof: { proof_type: "jwt", jwt: "eyJ..." } }
  let cnf; // confirmation claim for the credential
  try {
    const proofJwt =
      req.body.proofs?.jwt?.[0] || req.body.proof?.jwt;
    if (!proofJwt) throw new Error('no proof jwt in request');

    const headerB64 = proofJwt.split('.')[0];
    const header = JSON.parse(
      Buffer.from(headerB64, 'base64url').toString('utf8'),
    );

    if (header.jwk) {
      cnf = { jwk: header.jwk };
      console.log(`  -> holder key: jwk (kty=${header.jwk.kty})`);
    } else if (header.kid) {
      cnf = { kid: header.kid };
      console.log(`  -> holder key: kid (${header.kid.slice(0, 40)}...)`);
    } else {
      throw new Error('proof header has neither jwk nor kid');
    }
  } catch (e) {
    console.error(`  -> proof error: ${e.message}`);
    return res.status(400).json({
      error: 'invalid_proof',
      error_description: e.message,
      c_nonce: crypto.randomUUID(),
      c_nonce_expires_in: 86400,
    });
  }

  // Determine typ from credential_configuration_id or format
  const configId =
    req.body.credential_configuration_id ||
    req.body.credential_identifier;
  const requestedFormat = req.body.format;
  let typ = 'dc+sd-jwt';

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
        cnf,
        family_name: 'Doe',
        given_name: 'John',
        email: 'john.doe@example.com',
        birthdate: '1990-01-15',
      },
      { _sd: ['family_name', 'given_name', 'email', 'birthdate'] },
      { header: { typ, kid: ISSUER_KID } },
    );

    console.log(`  -> issued (${typ}), ${credential.length} bytes`);

    // OpenID4VCI draft 15+ response format
    res.json({
      credentials: [{ credential }],
    });
  } catch (err) {
    console.error('  -> issuance error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── Catch-all for debugging unknown requests ───────────────────────────────
app.use((req, res) => {
  console.log(`  -> 404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: 'not_found' });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const offerUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${BASE_URL}/credential-offer`)}`;

  const isHttps = BASE_URL.startsWith('https://');

  console.log(`
╔══════════════════════════════════════════════════════════╗
║         SD-JWT VC Credential Issuer (EUDI Wallet)       ║
╚══════════════════════════════════════════════════════════╝

  Server:     ${BASE_URL}
  JWKS:       ${BASE_URL}/jwks
  Formats:    dc+sd-jwt, vc+sd-jwt
  Issuer kid: ${ISSUER_KID}
  Offer:      ${offerUrl}
${!isHttps ? `
  WARNING: EUDI Wallet requires HTTPS. Use ngrok or similar:
    npx ngrok http ${PORT}
    BASE_URL=https://<id>.ngrok-free.app npm start
` : ''}
Scan this QR code with your EUDI Wallet app:
`);

  qrcode.generate(offerUrl, { small: true }, (code) => {
    console.log(code);
  });
});
