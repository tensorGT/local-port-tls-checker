# local-port-tls-checker

playing with `socket`, `asyncio`, and `ssl` in python for inspect open ports, service banners, and TLS certificates on my local machine.

## safety guard
- only allow `localhost`, `127.0.0.0/8`, private lab ranges (`10.x`, `172.16.x`, `192.168.x`), or explicit `--allow` hosts
- block scanning random public internet hosts
