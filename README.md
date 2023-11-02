# PID Issuer

## Summary

Implementation of a credential issuing service, according to
[OpenId4VCI - draft13](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html)

The service provides generic support for `mso_mdoc` and `SD-JWT-VC` formats using PID as an example
and requires the use of a suitable OAUTH2 server.

### OpenId4VCI coverage

| Feature                                                   | Coverage                                                  |
|-----------------------------------------------------------|-----------------------------------------------------------|
| Authorization Code flow                                   | Yes, using a suitable OAUTH2 server                       |
| Pre-authorized code flow                                  | No                                                        |
| mso_mdoc format                                           | Yes                                                       |
| SD-JWT-VC format                                          | Yes, except revocation list & meta                        |
| W3C VC DM                                                 | No                                                        |
| [Credential Endpoint](#credential-endpoint)               | Yes, including proofs, encryption, repeatable invocations |
| [Credential Issuer MetaData](#credential-issuer-metadata) | Yes, using `scopes`                                       | 
| Batch Endpoint                                            | No                                                        | 
| Deferred Endpoint                                         | No                                                        |
| Proof                                                     | Yes JWT (`jwk`, `x5c`) , CWT not supported                |



## Endpoints

### Credential Issuer MetaData

```bash
curl http://localhost:8080/.well-known/openid-credential-issuer | jq .
```

### Credential Endpoint


### Credentials Offer

Generate sample offer

```bash
curl http://localhost:8080/issuer/credentialsOffer | jq .
```

## Start keycloak

```bash
docker compose up
```

