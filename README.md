# Replay DW

Replay DW is a community Demonware-compatible backend for a compatible Call of Duty: Modern Warfare (2019) Replay game build. It lets compatible clients use selected online features through a server you run or join. It is an independent community project; it does not connect to or replace Activision's live services, and it does not include the game itself.

The repository contains the C++ server, Replay client integration, configuration and deployment tools, and technical guides. Support is build-specific and continues to evolve. Not every game service or mode is implemented, and a successful server build does not mean every in-game feature is ready. Check the feature guides and known limitations in [`docs/`](docs/) before planning a session.

## Local play on Windows (server and game on the same PC)

These steps build the **backend server** and connect an existing compatible DW client to it. You need a matching Replay 1.20 game installation and DW client package from your package provider. This source download does not include the game, and building the server does not create the game executable.

The client embeds trusted server public keys. Step 6 creates a separate local client using **your server's public key**, without rebuilding the game or changing the original client. You still need an existing compatible DW client and its game assets. Never copy production private keys into a local server.

### 1. Install the build tools

- Install **Visual Studio 2022** or **Build Tools for Visual Studio 2022**.
- In Visual Studio Installer, select **Desktop development with C++**, including the MSVC x64/x86 tools and a Windows SDK.
- Install **CMake 3.24 or newer** and select its option to add CMake to PATH.
- Open a new PowerShell window after installation.

Install **Python 3.10 or newer** for the one-time local-client setup in step 6. The Windows Python launcher (`py`) is used below; use `python` instead if that is how Python is installed on your PC. No extra Python packages are needed for setup. Python is not required to compile or run the backend itself.

### 2. Open the source folder

Extract the source ZIP into a folder such as `C:\Games\DW-1.20-main`. Keep it separate from the game installation. In PowerShell, change to that folder, replacing this example with your actual path:

```powershell
Set-Location -LiteralPath 'C:\Games\DW-1.20-main'
```

This folder must contain `CMakeLists.txt`, `build-server.ps1`, and `src`.

### 3. Build the backend server

```powershell
.\build-server.ps1
```

Wait for the command to finish without errors. It builds only `iw8-dw-server` and prints the SHA-256 hash of `build\Release\iw8-dw-server.exe`.

If PowerShell blocks the script, use the equivalent CMake commands below. Run each command separately and continue only when it succeeds:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --target iw8-dw-server --parallel 2
```

Do not run `build-game.ps1` for this step. That is the maintainer's game-client build and publication pipeline, and requires private compiler inputs absent from a source download.

### 4. Start your local server

From the same source folder, run:

```powershell
.\build\Release\iw8-dw-server.exe .\data\local-play
```

Leave this PowerShell window open. The server creates its own local accounts, keys, logs, and saved state in `data\local-play`. With no `network.json` in that folder, it uses loopback networking for this PC. Keep this folder between sessions so your server identity and progress persist; do not copy another server's runtime data into it.

This command runs the local executable directly. It does not publish to or control the project's remote server. The separate `start-server.ps1` helper can select remote administration when `data/primary-backend.json` exists, so it is not used in this walkthrough.

### 5. Check that it is ready

Open a second PowerShell window and run:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8085/health'
```

The response should identify the server as `iw8-dw`. You can also open [the local dashboard](http://127.0.0.1:8085/stats) in your browser. A healthy backend confirms server startup; the next step checks the game.

### 6. Set up your local client (once)

Close the game. Leave the local backend running. In a second PowerShell window,
open the **source folder** from step 2 and run the following. Replace the example
EXE path with the original DW executable in your actual game folder:

```powershell
py -3 tools/setup-local-client.py --client 'C:\Games\Replay\game_dx12_ship_replay_dw.exe' --server-data '.\data\local-play'
```

**Use the same data folder that your server is running with.** If you previously
started it with `.\data` instead, pass `--server-data '.\data'`. That folder must
already contain `platform-public.blob`; start the server once to create its keys.
Do not select a folder from another server or generate replacement keys every run.

The tool creates four files beside the original game EXE:

| File | Purpose |
| --- | --- |
| `game_dx12_ship_replay_local_dw.exe` | Separate client with your server's public key in platform, native-auth/content, and embedded-helper trust constants. |
| `game_dx12_ship_replay_local_dw.ini` | Selects `host=127.0.0.1` and `bypass_update_restart=1`. |
| `Run_Replay_DW_Local.cmd` | Starts the local client with the game folder as its working directory. |
| `game_dx12_ship_replay_local_dw.setup.json` | Records original/output hashes, public-key fingerprint, and changed byte ranges. |

Setup reads only the **public** key, preserves the original EXE and INI, and does
not edit the repository's client source or access the remote server. It checks
the PE layout and exact existing key constants before writing; an unsupported
or already-personalized EXE is rejected rather than guessed at. This produces a
local variant, not a verified production release artifact.

Automatic EXE, asset, and map updates are disabled for this local variant. Keep
`bypass_update_restart=1` in its INI, and install required maps/assets from your
compatible client package. A new local backend does not contain the production
server's downloadable packages. The original production client remains separate.

### 7. Play and check login

1. Keep the server from step 4 running.
2. In your **game folder**, double-click **Run_Replay_DW_Local.cmd**. Use this
   launcher, not the original production launcher.
3. Once signed in, enter Multiplayer and create a private match using an installed
   map. Use the available bot controls if desired.

If login fails, check `replay-dw-client.log` in the game folder. The latest launch
should show `host=127.0.0.1`, followed by `DW_LOCAL_PLATFORM_VERIFIED` when the
signed platform reply is accepted. That marker confirms the platform trust step;
native authentication and loading a match are subsequent checks.

The setup workflow has been checked against a real DW executable and fresh server
signatures using the actual game crypto verifier. Full game login and match play
still need testing on your installation. For failures, send the latest client log
and the setup JSON; do not send server private keys or player credentials.

This walkthrough is for one PC. LAN/internet play needs additional configuration
from [remote hosting](docs/remote-host-test.md); no router port forwarding is needed
for same-PC loopback play.

### 8. Stop, restart, or update

Close the game, then press **Ctrl+C** in the server window to stop the server. Next time, repeat step 4 and launch your client. Rebuild only after changing or updating the source. Back up `data\local-play` while the server is stopped. Runtime data is private and excluded from Git.

You do not need to rerun local-client setup on every launch. If you receive a newer
original DW EXE or deliberately replace your local server keys, close the game,
back up and move aside the four generated local-client files, then repeat step 6
using the untouched original EXE and the correct server data folder. Setup refuses
to overwrite existing local-client files. To return to production play, use your
original EXE, INI, and launcher.

### Common build and startup problems

| Message or symptom | What to do |
| --- | --- |
| `cmake` is not recognized | Install CMake, add it to PATH, and open a new PowerShell window. |
| No Visual Studio compiler found | Install the C++ workload and Windows SDK from step 1. |
| Missing `data/current-remote-deployment.json` | You ran the game-client pipeline. Use the server build in step 3. |
| Missing `DW_UpdateAssetPaths.h` | Use this updated source and the explicit `--target iw8-dw-server` command. The updater needs separate generated client inputs. |
| C2026 in `public_dashboard.h` | Update that header from this source; its dashboard is split into MSVC-compatible string literals. |
| CMake reports a different source directory or generator | Do not reuse a build folder copied from another machine. Rename that `build` folder, then configure again. |
| Server exits or health check fails | Read the server window and `data/local-play/server.log`. Check for another server using the same ports before starting a second copy. |
| Health check passes but the game cannot sign in | Check the matching client package, executable-specific INI, game working folder, and server log. A successful build does not prove client compatibility. |
| Missing `platform-public.blob` | Start your server once, then pass its actual runtime data folder to step 6. |
| Unsupported or already personalized client | Start from the untouched original `game_dx12_ship_replay_dw.exe`. Send the error and original EXE hash to the maintainer if its layout is unsupported. |
| Local client files already exist | Keep them for ordinary launches. To rerun setup, close the game, back them up and move all four aside first. |
| `server-platform-reply-signature-or-expiry` or an untrusted-key login error | Use `Run_Replay_DW_Local.cmd` and confirm setup used the same data folder as the running server. Keep the server keys between runs. If trust matches, check the Windows clock and send the latest client log. |

## Build the server on Linux

Install CMake 3.24+, a C++20 compiler, and OpenSSL 3 development files, then run:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target iw8-dw-server --parallel
./build/iw8-dw-server ./data/local-play
```

The game-client instructions above are for Windows. A server on a different machine requires the [remote hosting configuration](docs/remote-host-test.md).

For internet hosting, use the [native HTTPS setup](docs/server-tls.md). Remote
authentication, platform sessions, content requests, and updates use verified
TLS on port 8443. Local play on `127.0.0.1` keeps the simple HTTP setup above.
The Linux server rejects remote plaintext credential requests by default.

## Features and compatibility

The backend implements selected native authentication, platform, social, lobby, matchmaking, content, and progression services used by the compatible client. The exact supported operations and remaining gaps are documented in the topic guides under [`docs/`](docs/), including [matchmaking](docs/public-matchmaking.txt), [friends and player names](docs/player-names-and-friends.md), and [platform session persistence](docs/platform-session-persistence.txt).

Compatibility depends on the exact game executable, its configuration, and the assets installed by the player. Map packages are not supplied here. Some game modes require additional packages that may not be present in a given installation. Use only maps and modes available to all participants, and consult the relevant guide before testing them.

The configured DW droplet can distribute explicitly published custom maps through
the client updater. It checks for missing required files even when the EXE is
current. Map publication is separate from EXE releases, and previous server map
packages are backed up before replacement. See [custom map updates](docs/CUSTOM_MAP_UPDATES.txt).

## Development

The Replay client has one production target: `game_dx12_ship_replay_dw.exe`.
Its `build-game.ps1` / `deploy-game.ps1` workflow is for the configured maintainer
environment. It needs private recovered-game/compiler inputs and verified build
records that are not committed. The normal client build also publishes through
the configured remote release pipeline; it is not a standalone public build
command. Copying a deployment JSON alone does not supply the missing inputs.
The server build and direct local launch above do not invoke this workflow.
Client code lives in `integration/replay/` and `integration/host-scale/` as one
source set. See [the client build guide](docs/DW_CLIENT_BUILD.txt) for source
ownership, compilation evidence and the retirement of older revision targets.

The server is C++20 and built with CMake. Source lives under [`src/`](src/); Replay-specific integration is under [`integration/replay/`](integration/replay/). Start with [`CMakeLists.txt`](CMakeLists.txt), the feature guides in [`docs/`](docs/), and the existing contract tools under [`tools/`](tools/). On Windows, `format-backend.ps1 -Check` checks the C++ formatting without changing files.

Please keep runtime data, credentials, private keys, player identities, game files, and generated build outputs out of commits. Before submitting a change, build the affected target and run the focused checks documented with that feature. Clearly distinguish fixture results from tests using the actual game client.

## License and contributions

Check the repository's license and third-party notices before redistributing or contributing. Changes should target the `main` branch and include a concise description of the behavior changed and how it was verified.
