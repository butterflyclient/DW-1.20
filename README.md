# Replay DW

Replay DW is a community Demonware-compatible backend for a compatible Call of Duty: Modern Warfare (2019) Replay game build. It lets compatible clients use selected online features through a server you run or join. It is an independent community project; it does not connect to or replace Activision's live services, and it does not include the game itself.

The repository contains the C++ server, Replay client integration, configuration and deployment tools, and technical guides. Support is build-specific and continues to evolve. Not every game service or mode is implemented, and a successful server build does not mean every in-game feature is ready. Check the feature guides and known limitations in [`docs/`](docs/) before planning a session.

## Local play on Windows (server and game on the same PC)

These steps build the **backend server** and connect an existing compatible DW client to it. You need a matching Replay 1.20 game installation and DW client package from your package provider. This source download does not include the game, and building the server does not create the game executable.

**Local-play prerequisite:** the client embeds trusted server public keys. A newly initialized server creates its own keys, so changing a production client's `host` alone does not make it trust your server. Before attempting step 6, obtain a client prepared for your own server's public keys from the client maintainer. The public source download does not currently provide a standalone client bootstrap workflow. You can complete steps 1–5 to build and check the backend independently; they do not by themselves enable in-game local play. Never solve a key mismatch by copying the production server's private keys.

### 1. Install the build tools

- Install **Visual Studio 2022** or **Build Tools for Visual Studio 2022**.
- In Visual Studio Installer, select **Desktop development with C++**, including the MSVC x64/x86 tools and a Windows SDK.
- Install **CMake 3.24 or newer** and select its option to add CMake to PATH.
- Open a new PowerShell window after installation.

Python is not required for the server build or the direct local launch below.

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

### 6. Connect your DW game client

Complete this step only with a client prepared to trust this local server's keys, as described above.

1. Close the game before editing its configuration.
2. In the **game folder**, back up `game_dx12_ship_replay_dw.ini`, then open it in a text editor. If it does not exist, create it beside `game_dx12_ship_replay_dw.exe`. Make sure it is not saved as `.ini.txt`.
3. Set the existing `host` entry to `host=127.0.0.1`, or add that line if absent.
4. Keep the package's other required settings. A package configured for a remote guest may need a local-compatible identity/configuration from its provider; remote credentials are not automatically accounts on your new server.
5. Start the matching client using its supplied `Run_Replay_DW.cmd` from the game folder, with the local server still running.
6. Once signed in, enter Multiplayer and create a private match using a map included in your installation. Use the available bot controls if desired.

The executable-specific INI takes precedence over `replay-dw.ini`. Restart the client after changing it. This walkthrough is for one PC; LAN or internet play needs the additional setup in [remote hosting](docs/remote-host-test.md). No router port forwarding is needed for same-PC loopback play.

### 7. Stop and restart

Close the game, then press **Ctrl+C** in the server window to stop the server. Next time, repeat step 4 and launch your client. Rebuild only after changing or updating the source. Back up `data\local-play` while the server is stopped. Runtime data is private and excluded from Git.

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
| `server-platform-reply-signature-or-expiry` or an untrusted-key login error | Confirm that the client was prepared for this server's public keys. Changing `host` does not change the keys embedded in the client. Keep the local server's keys between runs. |

## Build the server on Linux

Install CMake 3.24+, a C++20 compiler, and OpenSSL 3 development files, then run:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target iw8-dw-server --parallel
./build/iw8-dw-server ./data/local-play
```

The game-client instructions above are for Windows. A server on a different machine requires the [remote hosting configuration](docs/remote-host-test.md).

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
