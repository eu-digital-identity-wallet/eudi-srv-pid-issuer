# PID Issuer

## Summary

Implementation of a credential issuing service, according to
[OpenId4VCI - draft13](https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html)

## Endpoints

### Credential Issuer MetaData

```bash
curl http://localhost:8080/.well-known/openid-credential-issuer | jq .
```

### Credentials Offer

Generate sample offer

```bash
curl http://localhost:8080/issuer/credentialsOffer | jq .
```

## Start keycloak

```bash
podman run --name keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  --network=host \
  quay.io/keycloak/keycloak:22.0.3 \
  start-dev \
  --http-port=8180
```

