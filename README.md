# Replay DW

Replay DW is a community Demonware-compatible backend for a compatible Call of Duty: Modern Warfare (2019) Replay game build. It lets compatible clients use selected online features through a server you run or join. It is an independent community project; it does not connect to or replace Activision's live services, and it does not include the game itself.

The repository contains the C++ server, Replay client integration, configuration and deployment tools, and technical guides. Support is build-specific and continues to evolve. Not every game service or mode is implemented, and a successful server build does not mean every in-game feature is ready. Check the feature guides and known limitations in [`docs/`](docs/) before planning a session.

## What you need

- A compatible Replay game installation and client package. This repository does not distribute game files.
- Windows 10/11 and Visual Studio 2022 C++ build tools for the included Windows build script; or CMake 3.24+, a C++20 compiler, and OpenSSL 3 development files to build on Linux.
- PowerShell for the Windows helper scripts.

## Build the server

On Windows, open PowerShell in this repository and run:

```powershell
./build-server.ps1
```

The Release server is written to `build/Release/iw8-dw-server.exe`. The script configures the project with CMake and compiles it; it also prints the resulting executable's SHA-256 hash.

On Linux, build with CMake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
```

The server requires a runtime data directory. Keep that directory private and backed up; it may contain signing keys, account state, player data, and logs. Runtime data is intentionally excluded from Git.

## Run locally

On Windows, start the server from PowerShell:

```powershell
./start-server.ps1
```

The helper starts the built server, creates the local runtime data directory, and checks its health endpoint. By default, the server is intended for local use. The included status, stop, and start scripts are `status-server.ps1`, `stop-server.ps1`, and `start-server.ps1`.

The local statistics page is served at `http://127.0.0.1:8085/stats`. It reports operational summaries and public lobby information; it does not provide server administration. Do not expose the server or dashboard to the internet unless you have reviewed the network and security guidance in this repository.

## Connect a Replay client

Use a client package that matches the server's supported Replay build. Follow the package's included launcher and INI instructions. The client INI selects the backend host; use `127.0.0.1` when the client and server run on the same computer. Restart the client after changing its INI.

For a private remote session, configure the host's advertised and local addresses, firewall, router forwarding, and each player's client settings as described in [`docs/remote-host-test.md`](docs/remote-host-test.md). Do not share server signing keys, runtime data, or another player's identity/profile files. Remote play requires compatible network configuration and is separate from local server startup.

## Features and compatibility

The backend implements selected native authentication, platform, social, lobby, matchmaking, content, and progression services used by the compatible client. The exact supported operations and remaining gaps are documented in the topic guides under [`docs/`](docs/), including [matchmaking](docs/public-matchmaking.txt), [friends and player names](docs/player-names-and-friends.md), and [platform session persistence](docs/platform-session-persistence.txt).

Compatibility depends on the exact game executable, its configuration, and the assets installed by the player. Map packages are not supplied here. Some game modes require additional packages that may not be present in a given installation. Use only maps and modes available to all participants, and consult the relevant guide before testing them.

## Development

The server is C++20 and built with CMake. Source lives under [`src/`](src/); Replay-specific integration is under [`integration/replay/`](integration/replay/). Start with [`CMakeLists.txt`](CMakeLists.txt), the feature guides in [`docs/`](docs/), and the existing contract tools under [`tools/`](tools/). On Windows, `format-backend.ps1 -Check` checks the C++ formatting without changing files.

Please keep runtime data, credentials, private keys, player identities, game files, and generated build outputs out of commits. Before submitting a change, build the affected target and run the focused checks documented with that feature. Clearly distinguish fixture results from tests using the actual game client.

## License and contributions

Check the repository's license and third-party notices before redistributing or contributing. Changes should target the `main` branch and include a concise description of the behavior changed and how it was verified.
