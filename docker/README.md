
## Docker image for DNS3L

`docker pull ghcr.io/dns3l/dns3ld`

### Configuration

Unfortunately `dns3ld` config YAML is actually not fully specified and implemented.
Visit [config-example.yaml](../config-example.yaml) and mount a custom config until this is stabilized.

| variable | note | default |
| --- | --- | --- |
| ENVIRONMENT | `production` or other deployments | |
| DNS3L_URL | URL for UI/UX | `https://localhost` |
| DNS3L_EMAIL | E-Mail contacts for UI/UX | `["info@example.com"]` |
| DNS3L_AUTH_URL | OIDC endpoint | `https://auth:5554/auth` |
| DNS_OTC_AK | OTC DNS access key ID | random |
| DNS_OTC_SK | OTC DNS secret access key | random |
| DNS_OTC_REGION | OTC DNS region | `eu-de` |
| STEP_RA_URL | Registration Authority URL | `https://sra:9443` |
| STEP_RA_FINGERPRINT | Registration Authority Fingerprint | `foobar` |
| DNS3L_DATABASE | MariaDB database name | `dns3l` |
| DNS3L_DB_USER | database user | `dns3l` |
| DNS3L_DB_PASS | user password | random |
| DNS3L_DB_HOST | MariaDB server IP/FQDN | `db` |
| MARIADB_ROOT_PASSWORD | MariaDB root password | |

If `ENVIRONMENT` is `! production` and `MARIADB_ROOT_PASSWORD` is set the database and user are created.

Mount a custom dns3ld config to `/etc/dns3ld.conf.yml` if environment based template seems not sufficient.
