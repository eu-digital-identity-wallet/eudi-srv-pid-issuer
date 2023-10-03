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
docker compose up
```

