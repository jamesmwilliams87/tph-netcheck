# TPH Net Check

Finds out why Neptune feels slow. Press **Run check** and it tests each layer in turn, then says which one is the problem:

| Step | What it measures | What it catches |
|---|---|---|
| Your connection | The adapter's negotiated speed, MTU, Wi-Fi or wired | Linked at 1, 2.5 or 5 Gb instead of 10. On Wi-Fi by mistake |
| Neptune's current load | CPU, busiest core, disk activity, RAM, RAID state, busiest processes | Data scrub, RAID rebuild, Cloud Sync, indexing or backups running |
| Ping and latency | Neptune, the building router, the internet | Packet loss, slow replies, upstream trouble |
| UniFi switches | Port speeds, errors, broadcast rate, spanning tree, loop events | Bad cables, loops, broadcast storms from the building network |
| Jumbo frames | Unfragmented large pings to Neptune | MTU mismatches that cause stalls |
| Network speed test | Raw speed both ways, disks not involved, with Neptune's CPU watched | Network faults, or Neptune's processor being the limit |
| File transfer test | Real SMB write and read with this machine's cache bypassed, Neptune's disks watched | Disk limits, competing work on Neptune, SMB or client problems |

Every result is saved in **History**, so a slow day can be compared with a normal one. **Isolation** lists every device the machine can reach, to confirm the studio VLAN is separate from other tenants.

## How it works

```
 Mac / PC                                     Neptune (DS1817)
 ┌──────────────────────┐   SSH, key only    ┌──────────────────────────┐
 │ TPH Net Check        │ ─────────────────▶ │ tph-netcheck-server      │
 │  link, ping, SMB     │   starts on demand │  load stats from /proc   │
 │  speed test client   │ ◀── TCP 5201 ────▶ │  speed test endpoint     │
 └──────────────────────┘                    │  exits when done         │
            │  HTTPS, read only               └──────────────────────────┘
            ▼
   UniFi controller (Dell laptop)
```

Nothing is installed or left running on Neptune. The app logs in over SSH with a dedicated key, runs the small test server for the length of the check, and the server exits on its own. The key is locked with a forced command, so it can only run the test server. It cannot open a shell, copy files or change anything.

## Layout

```
proto/        Types shared by the app and the Neptune server
server/       tph-netcheck-server, runs on Neptune (32-bit ARM, static)
core/         Diagnostic engine: tests, UniFi, verdict rules (36 unit tests)
app/          Tauri desktop app: src-tauri (Rust) and ui (HTML, CSS, JS)
.github/      Builds the Mac app, Windows installers and Neptune binary
```

## Building

Push this folder to a GitHub repository. The **Build** workflow produces:

- `tph-netcheck-mac`: a universal `.dmg` for Apple Silicon and Intel Macs
- `tph-netcheck-windows`: an `.msi` and a setup `.exe`
- `neptune-server`: `tph-netcheck-server-armv7-unknown-linux-musleabihf` is the one for Neptune

Push a tag such as `v0.1.0` and the same files are attached to a GitHub release.

To build on your own Mac instead: install Rust (`curl https://sh.rustup.rs -sSf | sh`) and Node, then:

```
cd app
npm install
npx tauri build --target universal-apple-darwin
```

The apps are not signed with an Apple or Microsoft certificate. On a Mac, the first time, right click the app and choose **Open**. On Windows, SmartScreen will warn once: choose **More info**, then **Run anyway**.

## Setting up Neptune (once)

You need an administrator login for Neptune and about 15 minutes.

**1. Turn on SSH and user homes.**
DSM: Control Panel > Terminal & SNMP > tick **Enable SSH service**.
Control Panel > User & Group > Advanced > tick **Enable user home service**. The key file lives in the user's home folder.

**2. Create the `netcheck` user.**
Control Panel > User & Group > Create. Name it `netcheck`, give it a long random password you never need to type, and add it to the **administrators** group. DSM only allows administrators to log in over SSH. The forced command in step 5 is what stops this account doing anything except running the test.

**3. Copy the test server onto Neptune.**
Create a folder `tools/tph-netcheck` on a share (the default path assumes a shared folder called `tools` on volume 1). Copy `tph-netcheck-server-armv7-unknown-linux-musleabihf` into it and rename it `tph-netcheck-server`.

**4. Make a key pair** on your Mac:

```
ssh-keygen -t ed25519 -N "" -C tph-netcheck -f ~/tph-netcheck-key
```

This creates `tph-netcheck-key` (private, goes into the app) and `tph-netcheck-key.pub` (public, goes on Neptune).

**5. Install the public key on Neptune.** SSH in with your own admin account and run these, pasting the contents of `tph-netcheck-key.pub` where shown:

```
sudo -i
chmod 755 /volume1/tools/tph-netcheck/tph-netcheck-server
uname -m        # should say armv7l
H=/var/services/homes/netcheck
mkdir -p $H/.ssh
echo 'command="/volume1/tools/tph-netcheck/tph-netcheck-server dispatch",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty PASTE-PUBLIC-KEY-HERE' > $H/.ssh/authorized_keys
chown -R netcheck:users $H
chmod 755 $H
chmod 700 $H/.ssh
chmod 600 $H/.ssh/authorized_keys
```

SSH ignores the key if the home folder or `.ssh` folder can be written by other users, which is why the permissions matter.

**6. Firewall.** If DSM's firewall is on, allow TCP port **5201** (the speed test) and your SSH port from the studio network only.

**7. Test from your Mac:**

```
ssh -i ~/tph-netcheck-key netcheck@NEPTUNE-IP version
```

It should print `tph-netcheck-server 0.1.0`. Try `ssh -i ~/tph-netcheck-key netcheck@NEPTUNE-IP` with no command: it should refuse with "command not allowed". That confirms the lock.

## Setting up UniFi (once)

On the Dell laptop's UniFi Network, add a local admin for the app with a **view only** role. Role names differ between UniFi versions; pick the one that cannot change settings. Use that username and password in the app. The app only reads from the controller.

## Setting up each machine

1. Mount the Neptune share the way you normally work. Make a folder `_netcheck` on it.
2. Install and open TPH Net Check, go to **Settings**:
   - **Address**: Neptune's IP address
   - **SSH key**: paste the contents of `tph-netcheck-key` (the private one) and click **Import key**. It is saved where only your user account can read it.
   - **Test folder**: for example `/Volumes/Projects/_netcheck` on the Mac, `Z:\_netcheck` on a PC
   - **UniFi controller**: `https://LAPTOP-IP:8443`, the view only user and its password. The password goes into the Mac Keychain or Windows Credential Manager.
3. Click **Test Neptune** and **Test UniFi**, then **Save**.
4. Add your own kit under **Known devices** for the isolation check: Saturn, the PCs, the printer and so on.

Each machine keeps two test files of the chosen size in `_netcheck` (4 GB per machine at the default 2 GB setting). It writes one and reads back the other, so the read figure comes from Neptune's disks and not its memory.

## Reading the results

- **Fault (red)**: something is wrong and fixable: a slow link, packet loss, a loop, a scrub during working hours.
- **Check (amber)**: a limit or something worth looking at, for example Neptune's processor or disks being the bottleneck.
- **Note (blue)**: context that might explain things.
- **OK (green)**: that layer is healthy.

Expect amber results about Neptune's processor. The DS1817's ARM chip can run out of CPU before the 10 Gb network fills. The app reports that as a hardware limit, not a network fault. Over time, History gives you hard numbers for the storage replan.

## Command-line runner

For testing without the app, the engine runs from a terminal using a settings file:

```
cargo run --release -p netcheck-core --example cli -- settings.json
```
