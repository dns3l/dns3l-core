# Ramp-up: minimal-dependency DNS3L config

This is a minimum config for dns3ld which works out of the box.
It contains 2 CA *bogus* providers which offer certificates from
a private CA. You need docker-compose, openssl and yq for this setup
to work. The setup is solely intended for development and evaluation.

Enter these commands to spin up a dns3ld instance together with mariadb:
```
./init # generates CAs and passwords. Requires openssl and yq.
docker compose build
docker compose up -d
```

After the docker-compose has started successfully, try out the API
with dns3lcli:
```
dns3lcli --no-auth --server http://localhost:8080 crt claim ca1 foo.bla.example.com
dns3lcli  --server http://localhost:8080 crt list
```

To clean up your workspace (deleting any generated stuff) you can enter:
```
docker compose down
./clean # destructive!
```
