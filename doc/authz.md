# dns3ld Authorization Model for OpenID Connect


| Authz Enabled | `write` set* | Identification Constraints | Behavior | Note |
|---|---|---|---|---|
| yes  | no | Must be set in OIDC token claims: `email` or `name`  | Allowed for read** access only to the root zones defined in `groups` array of OIDC token claims | An implicit `read` permission is assumed, even if not explicitily set in OIDC token claims |
| yes  | yes | Must be set in OIDC token claims: `email` | Allowed for read** and write** access, permitted root zones defined in `groups` array of OIDC token claims  |   |
| no | * | Must be set in OIDC token claims: `email` or `name` (read operation), `email` (write operation) | Allowed for read** and write** access, permitted root zones are **all** root zones defined in daemon config | |


\* String "write" checked case-insensitive in "groups" array of OIDC token claims

** See the description below for more info

### Read access
Permission to list generated certificates and see certificate details having their CN in the permitted root zones of the user. Additionally, permission to read the private key, certificate and certificate chain PEM data if the CN and all SANs are in the permitted root zones of the user.

### Write access
Permission to claim certificates for domain names having their CN and all SANs in the permitted root zones of the user. Additionally, permission to delete them if the CN is in the permitted root zones of the user.
