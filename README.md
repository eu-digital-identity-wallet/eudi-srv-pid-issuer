# PID Issuer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

* [Overview](#overview)
* [OpenId4VCI coverage](#openid4vci-coverage)
* [How to use docker]()
* [Endpoints](#endpoints)
* [How to contribute](#how-to-contribute)
* [License](#license)

## Overview

An implementation of a credential issuing service, according to
[OpenId4VCI - draft13](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html)

The service provides generic support for `mso_mdoc` and `SD-JWT-VC` formats using PID as an example
and requires the use of a suitable OAUTH2 server.

### OpenId4VCI coverage

| Feature                                                   | Coverage                                                  |
|-----------------------------------------------------------|-----------------------------------------------------------|
| Authorization Code flow                                   | ✅ Using a suitable OAUTH2 server                          |
| Pre-authorized code flow                                  | ❌                                                         |
| mso_mdoc format                                           | ✅                                                         |
| SD-JWT-VC format                                          | ✅ Except revocation list & meta                           |
| W3C VC DM                                                 | ❌                                                         |
| [Credential Endpoint](#credential-endpoint)               | Yes, including proofs, encryption, repeatable invocations |
| [Credential Issuer MetaData](#credential-issuer-metadata) | Yes, using `scopes`                                       | 
| Batch Endpoint                                            | ❌                                                         | 
| Deferred Endpoint                                         | ✅                                                         |
| Proof                                                     | ✅ JWT (`jwk`, `x5c`) , ❌ CWT               |

## How to use docker

Folder [docker-compose](docker-compose) contains the following services to be used in a local development environment:

### Keycloak

A Keycloak instance accessible via https://localhost/idp/ with the Realm *pid-issuer-realm*.

The Realm *pid-issuer-realm*:

- has user self-registration active with a custom registration page accessible via https://localhost/idp/realms/pid-issuer-realm/account/#/
- defines *eu.europa.ec.eudiw.pid_vc_sd_jwt* scope for requesting PID issuance in SD JWT VC format
- defines *eu.europa.ec.eudiw.pid_mso_mdoc* scope for requesting PID issuance in MSO MDOC format
- defines *wallet-dev* and *pid-issuer-srv* clients
- contains sample user with credentials: tneal / password

Administration console is accessible via https://localhost/idp/admin/ using the credentials admin / password

### PID Issuer

A PID Issuer instance accessible via https://localhost/pid-issuer/

It uses the configured Keycloak instance as an Authorization Server, and PID issuance both *SD JWT VC* and *MSO MDOC*
formats is enabled. Additionally *deferred issuance* is enabled for *SD JWT VC* format.

The issuing country is set to GR (Greece).

### HA Proxy

An HA Proxy instance is also configured. This instance exposes both Keyclaok and PID Issuer via https. The certificate
and respective private key can be found in [docker-compose/haproxy/certs](docker-compose/haproxy/certs).

### docker compose usage

```shell
cd docker-compose
docker-compose up -d
```

or

```shell
cd docker-compose
docker compose up -d
```

## Configuration

The PID Issuer application can be configured using the following *environment* variables:

Variable: `SPRING_PROFILES_ACTIVE`  
Description: Spring profiles to enable  
Default value: None. Enable `insecure` profile to disable SSL certificates verification  
---
Variable: `SPRING_WEBFLUX_BASE_PATH`  
Description: Context path for the PID issuer application.  
Default value: `/`
---
Variable: `SERVER_PORT`  
Description: Port for the HTTP listener of the PID Issuer application  
Default value: `8080`
---
Variable: `SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_ID`  
Description: Client Id of the OAuth2 client registered in the Authorization Server  
Default value: N/A
---
Variable: `SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_SECRET`  
Description: Client Server of the OAuth2 client registered in the Authorization Server  
Default value: N/A
---
Variable: `ISSUER_PUBLICURL`  
Description: URL the PID Issuer application is accessible from  
Default value: `http://localhost:${SERVER_PORT}${SPRING_WEBFLUX_BASE_PATH}`  
---
Variable: `ISSUER_AUTHORIZATIONSERVER`  
Description: URL of the Authorization Server  
Default value: N/A
---
Variable: `ISSUER_AUTHORIZATIONSERVER_INTROSPECTION`  
Description: URL of the Token Introspection endpoint of the Authorization Server  
Default value: N/A
---
Variable: `ISSUER_AUTHORIZATIONSERVER_USERINFO`  
Description: URL of the UserInfo endpoint of the Authorization Server  
Default value: N/A
---
Variable: `ISSUER_PID_MSO_MDOC_ENABLED`  
Description: Whether to enable support for PID issuance in *MSO MDOC* format  
Default value: `true`
---
Variable: `ISSUER_PID_SD_JWT_VC_ENABLED`  
Description: Whether to enable support for PID issuance in *SD JWT VC* format  
Default value: `true`
---
Variable: `ISSUER_PID_SD_JWT_VC_DEFERRED`  
Description: Whether PID issueance in *SD JWT VC* format should be *deferred* or *immediate*  
Default value: `false` (i.e. immediate issuance)
---
Variable: `ISSUER_PID_ISSUING_COUNTRY`  
Description: Code of the Country issuing the PID  
Default value: N/A

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

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.