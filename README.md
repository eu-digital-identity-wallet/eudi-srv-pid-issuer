# PID Issuer

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

* [Overview](#overview)
* [OpenId4VCI coverage](#openid4vci-coverage)
* [How to use docker](#how-to-use-docker)
* [Configuration](#configuration)
* [Endpoints](#endpoints)
* [How to contribute](#how-to-contribute)
* [License](#license)

## Overview

An implementation of a credential issuing service, according to [OpenId4VCI - v1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

The service provides generic support for `mso_mdoc` and `SD-JWT-VC` formats using PID, mDL, and European Health Insurance Card as an example
and requires the use of a suitable OAuth 2.0 server.

| Credential/Attestation         | Format    |
|--------------------------------|-----------|
| PID                            | mso_mdoc  |
| PID                            | SD-JWT VC |
| mDL                            | mso_mdoc  | 
| European Health Insurance Card | SD-JWT VC |

### OpenId4VCI coverage

| Feature                                                   | Coverage                                                           |
|-----------------------------------------------------------|--------------------------------------------------------------------|
| Authorization Code flow                                   | ✅ Using a suitable OAuth 2.0 server                                |
| Pre-authorized code flow                                  | ❌                                                                  |
| mso_mdoc format                                           | ✅                                                                  |
| SD-JWT-VC format                                          | ✅ Except revocation list & meta                                    |
| W3C VC DM                                                 | ❌                                                                  |
| Credential Offer                                          | ✅ `authorization_code` , ❌ `pre-authorized_code`                   |
| [Credential Endpoint](#credential-endpoint)               | Yes, including multiple proofs, encryption, repeatable invocations |
| [Credential Issuer MetaData](#credential-issuer-metadata) | Yes, using `scopes`, and `signed_metadata`                         | 
| Deferred Endpoint                                         | ✅                                                                  |
| Nonce Endpoint                                            | ✅                                                                  |
| Notification Endpoint                                     | ✅                                                                  |
| Proof                                                     | ✅ JWT (`jwk`, `x5c`, `did:key`, `did:jwk`, `key-attestation`)      |
|                                                           | ✅ attestation                                                      |
|                                                           | ❌ Data Integrity Proof                                             |

## How to use docker

Folder [docker-compose](docker-compose) contains the following services to be used in a local development environment:

### Keycloak

A Keycloak instance accessible via https://localhost/idp/ with the Realm *pid-issuer-realm*.

The Realm *pid-issuer-realm*:

- has user self-registration active with a custom registration page accessible
  via https://localhost/idp/realms/pid-issuer-realm/account/#/
- defines *eu.europa.ec.eudi.pid_vc_sd_jwt* scope for requesting PID issuance in SD-JWT VC format
- defines *eu.europa.ec.eudi.pid_mso_mdoc* scope for requesting PID issuance in MSO MDOC format
- defines *org.iso.18013.5.1.mDL* scope for requesting mDL issuance in MSO MDOC format
- defines *urn:eudi:ehic:1:dc+sd-jwt* scope for requesting European Health Insurance Card issuance in SD-JWT VC format
- defines *wallet-dev* and *pid-issuer-srv* clients
- contains sample user with credentials: tneal / password

The Administration console is accessible via https://localhost/idp/admin/ using the credential admin / password

### Issuer

An Issuer instance accessible via https://localhost/pid-issuer/

It uses the configured Keycloak instance as an Authorization Server, and supports issuing of PID, mDL, and European Health Insurance Card.
Additionally, *deferred issuance* is enabled for PID in *SD JWT VC* format.

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
Description: Spring profiles to enable. Enable `insecure` profile to disable SSL certificates verification.  
Default value: N/A 

Variable: `SPRING_WEBFLUX_BASE_PATH`  
Description: Context path for the PID issuer application.  
Default value: `/`

Variable: `SERVER_PORT`  
Description: Port for the HTTP listener of the PID Issuer application  
Default value: `8080`

Variable: `SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_ID`  
Description: Client Id of the OAuth 2.0 client registered in the Authorization Server  
Default value: N/A

Variable: `SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_SECRET`  
Description: Client Server of the OAuth 2.0 client registered in the Authorization Server  
Default value: N/A

Variable: `SERVER_FORWARD_HEADERS_STRATEGY`  
Description: Whether the server should consider X-Forwarded headers. In case the application is behind a reverse proxy,
set this to `FRAMEWORK`.  
Possible values: `FRAMEWORK`, `NONE`  
Default value: `FRAMEWORK`  

Variable: `SPRING_WEBFLUX_CODECS_MAX_IN_MEMORY_SIZE`  
Description: Configure a limit on the number of bytes that can be buffered whenever the input stream needs to be aggregated. Uses Spring Framework's DataSize notation.         
Default value: `1MB`

Variable: `ISSUER_PUBLICURL`  
Description: URL the PID Issuer application is accessible from  
Default value: `http://localhost:8080`

Variable: `ISSUER_AUTHORIZATIONSERVER_PUBLICURL`  
Description: URL of the Authorization Server advertised via the issuer metadata    
Default value: N/A  

Variable: `ISSUER_AUTHORIZATIONSERVER_METADATA`  
Description: URL used to fetch the metadata of the Authorization Server      
Default value: N/A

Variable: `ISSUER_AUTHORIZATIONSERVER_INTROSPECTION`  
Description: URL of the Token Introspection endpoint of the Authorization Server  
Default value: N/A

Variable: `ISSUER_CREDENTIALRESPONSEENCRYPTION_SUPPORTED`  
Description: Whether to enable support for credential response encryption.    
Default value: `true`

Variable: `ISSUER_CREDENTIALRESPONSEENCRYPTION_REQUIRED`  
Description: Whether credential response encryption is required.  
Default value: `true`

Variable: `ISSUER_CREDENTIALRESPONSEENCRYPTION_ALGORITHMSSUPPORTED`  
Description: Comma separated list of supported encryption algorithms for credential response encryption.      
Default value: `ECDH-ES`

Variable: `ISSUER_CREDENTIALRESPONSEENCRYPTION_ENCRYPTIONMETHODS`  
Description: Comma separated list of supported encryption method for credential response encryption.      
Default value: `A128GCM`

Variable: `ISSUER_PID_MSO_MDOC_ENABLED`  
Description: Whether to enable support for PID issuance in *MSO MDOC* format  
Default value: `true`

Variable: `ISSUER_PID_MSO_MDOC_ENCODER_DURATION`    
Description: Configures the validity of issued PIDs in *MSO MDOC* format. Uses Period syntax. 
Default value: `P30D`

Variable: `ISSUER_PID_MSO_MDOC_NOTIFICATIONS_ENABLED`  
Description: Whether to enabled Notifications Endpoint support for PIDs issued in *MSO MDOC*.     
Default value: `true`

Variable: `ISSUER_PID_MSO_MDOC_JWTPROOFS_SUPPORTEDSIGNINGALGORITHMS`      
Description: Comma separated list of the signing algorithms that can be used with JWT Proofs.      
Default value: `ES256`

Variable: `ISSUER_PID_MSO_MDOC_KEY_ATTESTATIONS_REQUIRED`      
Description: Boolean property that when set to true makes key attestations mandatory in proofs sent for issuance of PID attestations in msoMdoc format. A key attestation is expected in a JWT proof or as a proof itself.
Default value: N/A

Variable: `ISSUER_PID_MSO_MDOC_KEY_ATTESTATIONS_CONSTRAINTS_KEY_STORAGE`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the storage of keys included in a key attestation.  
Default value: N/A

Variable: `ISSUER_PID_MSO_MDOC_KEY_ATTESTATIONS_CONSTRAINTS_USER_AUTHENTICATION`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the authentication of user when using the keys included in the key attestation.
Default value: N/A

Variable: `ISSUER_PID_SD_JWT_VC_ENABLED`  
Description: Whether to enable support for PID issuance in *SD JWT VC* format.  
Default value: `true`

Variable: `ISSUER_PID_SD_JWT_VC_DURATION`  
Description: Configures the validity of issued PIDs in *SD JWT VC* format. Uses Period syntax.  
Default value: `P30D`

Variable: `ISSUER_PID_SD_JWT_VC_NOTUSEBEFORE`  
Description: Period after which a PID issued in *SD JWT VC* becomes valid. Used to calculate the value of the `nbf` claim.  
Default value: `PT20S`

Variable: `ISSUER_PID_SD_JWT_VC_NOTIFICATIONS_ENABLED`  
Description: Whether to enabled Notifications Endpoint support for PIDs issued in *SD JWT VC*.  
Default value: `true`

Variable: `ISSUER_PID_SD_JWT_VC_DIGESTS_HASHALGORITHM`  
Description: Hash algorithm used to calculate the disclosure digests of PIDs issued in *SD JWT VC*.   
Allowed values: `sha-256`, `sha-384`, `sha-512`, `sha3-256`, `sha3-384`, `sha3-512`   
Default value: `sha-256`

Variable: `ISSUER_PID_SD_JWT_VC_JWTPROOFS_SUPPORTEDSIGNINGALGORITHMS`      
Description: Comma separated list of the signing algorithms that can be used with JWT Proofs.      
Default value: `ES256`

Variable: `ISSUER_PID_SD_JWT_VC_KEY_ATTESTATIONS_REQUIRED`      
Description: Boolean property that when set to true makes key attestations mandatory in proofs sent for issuance of PID attestations in sd-jwt-vc format. A key attestation is expected in a JWT proof or as a proof itself.
Default value: N/A

Variable: `ISSUER_PID_SD_JWT_VC_KEY_ATTESTATIONS_CONSTRAINTS_KEY_STORAGE`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the storage of keys included in a key attestation.  
Default value: N/A

Variable: `ISSUER_PID_SD_JWT_VC_KEY_ATTESTATIONS_CONSTRAINTS_USER_AUTHENTICATION`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the authentication of user when using the keys included in the key attestation.
Default value: N/A

Variable: `ISSUER_PID_ISSUINGCOUNTRY`  
Description: Code of the Country issuing the PID  
Default value: `GR`

Variable: `ISSUER_PID_ISSUINGJURISDICTION`  
Description: Country subdivision code of the jurisdiction issuing the PID  
Default value: `GR-I`  

Variable: `ISSUER_MDL_ENABLED`    
Description: Whether to enable support for issuing mDL.    
Default value: `true`

Variable: `ISSUER_MDL_MSO_MDOC_ENCODER_DURATION`    
Description: Configures the validity of issued mDLs when using the internal encoder. Uses Period syntax. 
Required when `ISSUER_MDL_MSO_MDOC_ENCODER` is set to `Internal`.  
Default value: `P5D`

Variable: `ISSUER_MDL_NOTIFICATIONS_ENABLED`    
Description: Whether to enabled Notifications Endpoint support for mDLs.    
Default value: `true`

Variable: `ISSUER_MDL_JWTPROOFS_SUPPORTEDSIGNINGALGORITHMS`      
Description: Comma separated list of the signing algorithms that can be used with JWT Proofs.      
Default value: `ES256`

Variable: `ISSUER_MDL_KEY_ATTESTATIONS_REQUIRED`      
Description: Boolean property that when set to true makes key attestations mandatory in proofs sent for issuance of PID attestations in msoMdoc format. A key attestation is expected in a JWT proof or as a proof itself.
Default value: N/A

Variable: `ISSUER_MDL_KEY_ATTESTATIONS_CONSTRAINTS_KEY_STORAGE`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the storage of keys included in a key attestation.  
Default value: N/A

Variable: `ISSUER_MDL_KEY_ATTESTATIONS_CONSTRAINTS_USER_AUTHENTICATION`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the authentication of user when using the keys included in the key attestation.
Default value: N/A

Variable: `ISSUER_EHIC_ENABLED`    
Description: Whether to enabled support for issuing European Health Insurance Cards in *SD-JWT VC* format.    
Default value: `true`

Variable: `ISSUER_EHIC_VALIDITY`    
Description: Validity of European Health Insurance Cards issued in *SD-JWT VC* format. Uses Period syntax.      
Default value: `P30D`

Variable: `ISSUER_EHIC_ENCODER_DIGESTS_HASHALGORITHM`  
Description: Hash algorithm used to calculate the disclosure digests of European Health Insurance Cards issued in *SD-JWT VC* format.    
Allowed values: `sha-256`, `sha-384`, `sha-512`, `sha3-256`, `sha3-384`, `sha3-512`   
Default value: `sha-256`  

Variable: `ISSUER_EHIC_NOTIFICATIONS_ENABLED`    
Description: Whether to enabled Notifications Endpoint support for European Health Insurance Cards issued in *SD-JWT VC* format.    
Default value: `true`

Variable: `ISSUER_EHIC_ISSUINGCOUNTRY`      
Description: Issuing Country used for European Health Insurance Cards issued in *SD-JWT VC* format. 2-letter ISO Country Code.      
Default value: `GR`  

Variable: `ISSUER_EHIC_JWTPROOFS_SUPPORTEDSIGNINGALGORITHMS`      
Description: Comma separated list of the signing algorithms that can be used with JWT Proofs.      
Default value: `ES256`  

Variable: `ISSUER_EHIC_KEY_ATTESTATIONS_REQUIRED`      
Description: Boolean property that when set to true makes key attestations mandatory in proofs sent for EHIC attestation issuance. A key attestation is expected in a JWT proof or as a proof itself.
Default value: N/A

Variable: `ISSUER_EHIC_KEY_ATTESTATIONS_CONSTRAINTS_KEY_STORAGE`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the storage of keys included in a key attestation.  
Default value: N/A

Variable: `ISSUER_EHIC_KEY_ATTESTATIONS_CONSTRAINTS_USER_AUTHENTICATION`      
Description: Comma separated list of strings. Each string specifies an accepted level of attack resistance protection regarding the authentication of user when using the keys included in the key attestation. 
Default value: N/A

Variable: `ISSUER_CREDENTIALOFFER_URI`    
Description: URI to use when generating Credential Offers.    
Default value: `openid-credential-offer://`

Variable: `ISSUER_SIGNING_KEY`  
Description: Whether to generate a new, or use an existing key-pair for signing verifiable credentials.    
Possible values: `GenerateRandom`, `LoadFromKeystore`  
Default value: `GenerateRandom`

Variable: `ISSUER_SIGNING_KEY_KEYSTORE`  
Description: Location of the keystore from which to load the key-pair for signing verifiable credentials. Uses Spring Resource URL syntax.       
Default value: N/A

Variable: `ISSUER_SIGNING_KEY_KEYSTORE_TYPE`  
Description: Type of the keystore from which to load the key-pair for signing verifiable credentials.       
Default value: N/A

Variable: `ISSUER_SIGNING_KEY_KEYSTORE_PASSWORD`  
Description: Password of the keystore from which to load the key-pair for signing verifiable credentials.       
Default value: N/A

Variable: `ISSUER_SIGNING_KEY_ALIAS`  
Description: Alias of the key-pair for signing verifiable credentials.       
Default value: N/A

Variable: `ISSUER_SIGNING_KEY_PASSWORD`  
Description: Password of the key-pair for signing verifiable credentials.       
Default value: N/A

Variable: `ISSUER_METADATA_SIGNED_METADATA_ENABLED`  
Description: Whether to enable support for signed metadata or not.  
Default value: `true`  

Variable: `ISSUER_METADATA_SIGNED_METADATA_ISSUER`  
Description: Value of the `iss` claim of the signed metadata.  
Default value: Value of `ISSUER_PUBLICURL`

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY`  
Description: Whether to generate a new, or use an existing key-pair for signing metadata.    
Possible values: `GenerateRandom`, `LoadFromKeystore`  
Default value: `GenerateRandom`

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY_KEYSTORE`  
Description: Location of the keystore from which to load the key-pair for signing metadata. Uses Spring Resource URL syntax.       
Default value: N/A

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY_KEYSTORE_TYPE`  
Description: Type of the keystore from which to load the key-pair for signing metadata.       
Default value: N/A

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY_KEYSTORE_PASSWORD`  
Description: Password of the keystore from which to load the key-pair for signing metadata.       
Default value: N/A

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY_ALIAS`  
Description: Alias of the key-pair for signing metadata.       
Default value: N/A

Variable: `ISSUER_METADATA_SIGNED_METADATA_SIGNING_KEY_PASSWORD`  
Description: Password of the key-pair for signing metadata.       
Default value: N/A

Variable: `ISSUER_KEYCLOAK_SERVER_URL`  
Description: URL of the Keycloak authorization server  
Default value: N/A  
Example: https://localhost/idp  

Variable: `ISSUER_KEYCLOAK_AUTHENTICATION_REALM`  
Description: Authentication realm for the administrator user of Keycloak  
Default value: N/A  
Example: master  

Variable: `ISSUER_KEYCLOAK_CLIENT_ID`  
Description: Id of the OAuth 2.0 client used for management of Keycloak   
Default value: N/A  
Example: admin-cli  

Variable: `ISSUER_KEYCLOAK_USERNAME`  
Description: Username of the Keycloak administrator user  
Default value: N/A  
Example: admin  

Variable: `ISSUER_KEYCLOAK_PASSWORD`  
Description: Password of the Keycloak administrator user  
Default value: N/A  
Example: password

Variable: `ISSUER_KEYCLOAK_USER_REALM`  
Description: Realm of the administered users in Keycloak   
Default value: N/A  
Example: password

Variable: `ISSUER_DPOP_PROOF_MAX_AGE`  
Description: Max duration a DPoP Access Token is considered active      
Default value: `PT1M`  

Variable: `ISSUER_DPOP_CACHE_PURGE_INTERVAL`  
Description: Interval after which cached DPoP Access Tokens are deleted         
Default value: `PT10M`

Variable: `ISSUER_DPOP_REALM`  
Description: Realm to report in the WWW-Authenticate header in case of DPoP authentication/authorization failure         
Default value: `pid-issuer`

Variable: `ISSUER_DPOP_NONCE_ENABLED`  
Description: Whether Nonce values are required for DPoP authentication    
Default value: `true`

Variable: `ISSUER_DPOP_NONCE_EXPIRATION`  
Description: Duration after which Nonce values for DPoP authentication expire    
Default value: `PT5M`

Variable: `ISSUER_CREDENTIALENDPOINT_BATCHISSUANCE_ENABLED`  
Description: Whether to enable batch issuance support in the credential endpoint         
Default value: `true`

Variable: `ISSUER_CREDENTIALENDPOINT_BATCHISSUANCE_BATCHSIZE`  
Description: Maximum length of `proofs` array supported by credential endpoint when batch issuance support is enabled          
Default value: `10`

Variable: `ISSUER_CNONCE_EXPIRATION`  
Description: Duration after which CNonce values expire    
Default value: `PT5M`

Variable: `ISSUER_STATUSLIST_ENABLED`  
Description: Whether to enable support for Status List Tokens      
Default value: `false`

Variable: `ISSUER_STATUSLIST_SERVICE_URI`  
Description: URI of the service used to generate Status List Tokens  

Variable: `ISSUER_STATUSLIST_SERVICE_APIKEY`  
Description: API Key of the service used to generate Status List Tokens

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS`  
Description: Whether to generate a new, or use an existing key-pair for credential request encryption.    
Possible values: `GenerateRandom`, `LoadFromKeystore`  
Default value: `GenerateRandom`

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_KEYSTORE`   
Description: Location of the keystore from which to load the key-pair for credential request encryption. Uses Spring Resource URL syntax.  
Default value: N/A

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_KEYSTORE_TYPE`   
Description: Type of the keystore from which to load the key-pair for credential request encryption.  
Default value: N/A

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_KEYSTORE_PASSWORD`   
Description: Password of the keystore from which to load the key-pair for credential request encryption.  
Default value: N/A  

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_ALIAS`  
Description: Alias of the key-pair for credential request encryption.    
Default value: N/A  

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_PASSWORD`  
Description: Password of the key-pair for credential request encryption.  
Default value: N/A

Variable: `ISSUER_CREDENTIALREQUESTENCRYPTION_JWKS_ALGORITHM`  
Description: The algorithm of the key for credential request encryption.  
Default value: N/A

Variable: `ISSUER_NONCE_ENCRYPTION_KEY`  
Description: Whether to generate a new, or use an existing EC key-pair for nonce encryption.      
Possible values: `GenerateRandom`, `LoadFromKeystore`    
Default value: `GenerateRandom`

Variable: `ISSUER_NONCE_ENCRYPTION_KEY_KEYSTORE`  
Description: Location of the keystore from which to load the EC key-pair for nonce encryption. Uses Spring Resource URL syntax.  
Default value: N/A

Variable: `ISSUER_NONCE_ENCRYPTION_KEY_KEYSTORE_TYPE`  
Description: Type of the keystore from which to load the EC key-pair for nonce encryption.  
Default value: N/A

Variable: `ISSUER_NONCE_ENCRYPTION_KEY_KEYSTORE_PASSWORD`  
Description: Password of the keystore from which to load the EC key-pair for nonce encryption.  
Default value: N/A

Variable: `ISSUER_NONCE_ENCRYPTION_KEY_ALIAS`  
Description: Alias of the EC key-pair for nonce encryption.  
Default value: N/A

Variable: `ISSUER_NONCE_ENCRYPTION_KEY_PASSWORD`  
Description: Password of the EC key-pair for nonce encryption.  
Default value: N/A

### Metadata configuration

You can configure the display objects of the Credential Issuer Metadata of PID Issuer, using the following 
environment variables. 
For each display object you must configure as a bare minimum either the name or the logo uri.
Only one display object can be configured per locale.

Replace `XX` with the index of the display object you want to configure.

Variable: `ISSUER_METADATA_DISPLAY_XX_NAME` (e.g. `ISSUER_METADATA_DISPLAY_0_NAME`)    
Description: Display name for the Credential Issuer  

Variable: `ISSUER_METADATA_DISPLAY_XX_LOCALE` (e.g. `ISSUER_METADATA_DISPLAY_0_LOCALE`)    
Description: Language tag of this display object  

Variable: `ISSUER_METADATA_DISPLAY_XX_LOGO_URI` (e.g. `ISSUER_METADATA_DISPLAY_0_LOGO_URI`)  
Description: URI where the Wallet can obtain the logo of the Credential Issuer  

Variable: `ISSUER_METADATA_DISPLAY_XX_LOGO_ALTERNATIVETEXT` (e.g. `ISSUER_METADATA_DISPLAY_0_LOGO_ALTERNATIVETEXT`)  
Description: Alternative text for the logo image  

### SD-JWT VC Type Metadata configuration

You can configure the Type Metadata of PID Issuer, using the following
environment variables.  
Each VCT should be configured once.

Variable: `ISSUER_SD_JWT_VC_TYPE_METADATA_XX_VCT` (e.g. `ISSUER_SD_JWT_VC_TYPE_METADATA_0_VCT`)  
Description: The VCT of the type metadata property 
Example: `urn:eudi:pid:1`  

Variable: `ISSUER_SD_JWT_VC_TYPE_METADATA_XX_RESOURCE` (e.g. `ISSUER_SD_JWT_VC_TYPE_METADATA_0_RESOURCE`)  
Description: Resource of the type metadata, using spring framework resource notation 
Example: `classpath:/vct/pid_v1.2.json` or `file:///vct/pid_v1.2.json`

### Proxy configuration

Variable: `ISSUER_HTTP_PROXY_URL`  
Description: Set verifier proxy URL to use  
Example: `http://exmaple.com`

Variable: `ISSUER_HTTP_PROXY_USERNAME`  
Description: Set proxy username for proxy to use  
Example: `username`

Variable: `ISSUER_HTTP_PROXY_PASSWORD`  
Description: Set proxy password for proxy to use  
Example: `passwd`

### Signing Key

When either PID issuance in SD-JWT is enabled, or the internal MSO MDoc encoder is used, an EC Key is required 
for signing the issued credentials.

By default, the server generates a random EC Key alongside a self-signed certificate using the *P-256/secp256r1* 
curve on startup. If the server is restarted, a new EC Key and self-signed certificate is generated.

> [!TIP]
> In case you opt to use your own EC Key and certificate, 
> make sure to use an EC Key that uses one of the following curves:
> - *P-256/secp256r1*
> - *P-384/secp384r1*
> - *P-521/secp521r1*

The EC Key used determines the signing algorithm. The server will use one of the following signing algorithms:
- *ES256*
- *ES384*
- *ES512*

To generate an EC Key and self-signed certificate using `keytool` you can use the following command:

```bash
keytool -genkeypair \
  -alias signingKey \
  -keyalg EC \
  -groupname secp256r1 \
  -sigalg SHA256withECDSA \
  -validity 365 \
  -dname "CN=pid-issuer" \
  -storetype JKS \
  -keystore signingKey.jks \
  -storepass 123456 \
  -keypass 654321
```

This command will create a *JKS* keystore named *signingKey.jks* in the current directory, protected by the 
password *123456*. The keystore will contain an EC Key generated using the curve *P-256/secp256r1* and a self-signed
certificate signed using the algorithm *SHA256withECDSA*, with the alias *signingKey*, protected with the 
password *654321*.

__Note__: When loading an EC Key and certificate from a keystore, make sure the certificate chain is associated with
the EC Key alias.

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

### Retrieve Type MetaData

```bash
curl http://localhost:8080/type-metadata/urn:eudi:pid:1
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
