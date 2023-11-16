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

Folder [keycloak](keycloak) contains a keycloak installation to be used in a local development environment


```shell
cd keycloak
docker-compose up -d
```


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