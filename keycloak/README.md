# install keycloak

set to your hosts file:
[IP ADDRESS OF YOUR LAPTOP] keycloak.local

NOTE: do not use 127.0.0.1 for your IP Address, use the actual IP Address of your laptop.

in the vm you run the wallet app, the JVM needs the Keycloak localhost 
certificate in the trust list, for the latter use:

```bash
sudo keytool -import \
  -trustcacerts \
  --cacerts \
  -alias keycloaklocalAlias \
  -file ./haproxy/certs/localhost.tls.crt \
  -storepass changeit \
  -noprompt
```