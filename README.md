# zteOnu

A single-file Go tool to interact with ZTE ONU factory mode.

> For security research and your own devices only.

## Build

```bash
go build -o zte_onu .
```

## Usage

```bash
./zte_onu <ip> -m <your-mac> [options]
```

| Option | Required | Description |
|--------|:---:|-------------|
| `ip` | — | Device IP (or use `-ip`) |
| `-m` | —  | Your NIC MAC, e.g. `AA:BB:CC:DD:EE:FF` |
| `-port` | — | Web port (default `8080`) |
| `-u, -user` | — | Username(s), multiple allowed |
| `-p, -pass` | — | Password(s), multiple allowed |
| `-slaveip` | — | Append `&slaveip=<ip>` to step 5 |
| `-close` | — | Close factory mode |
| `-all` | — | Try all credentials, don't stop on first hit |
| `-v` | — | Verbose output |

`-u` and `-p` pair up 1:1. If one side has a single value, it is broadcast to match the other.

## Examples

```bash
# Basic
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF

# Verbose
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -v

# Custom credentials
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -u telecomadmin -p 'nE7jA%5m'

# Multiple credential pairs
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -u admin -u root -p admin -p toor

# Try all pairs
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -all

# Close factory mode
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -close

# Slave ONU
./zte_onu 192.168.1.1 -m AA:BB:CC:DD:EE:FF -slaveip 192.168.1.2
```

## Output

```
[1/4] user=factorymode pass=nE%jA@5b -> OK  1:OK 2:OK 3:OK 4:OK 5:OK  core=A seed=37
Hit: user=factorymode pass=nE%jA@5b -> user=telecomadmin  pass=nE7jA%5m
```

- `facStep 1~5` are the five handshake steps.
- `core` is the auto-detected branch (`A`, `B`, `C`, `M`).
- step4 codes: `401` = bad credentials or format, `400` = stale state (retry).

## License

AGPL-3.0. See [LICENSE](LICENSE).
