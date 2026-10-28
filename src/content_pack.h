#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace content_pack
{
    using Log = std::function<void(const std::string &)>;

    // The content root beside a backend checkout or release (content/<pack>/),
    // searched from the running executable's directory upwards.
    std::optional<std::filesystem::path> locate();

    // Installs every pack under root into data. A file is written only when it
    // is missing, or when it still holds the bytes an earlier pack revision
    // installed; operator-published replacements are kept. Nothing is deleted.
    void install(const std::filesystem::path &data, const std::filesystem::path &root, const Log &log);

    // Local-play setup for a loopback-only server: a dashboard operator key and,
    // when local-play.json names the game folder, the installed-map inventory
    // (playlists/<title>/packages.json) that restricts matchmaking to maps the
    // local installation actually has.
    void prepareLocalPlay(const std::filesystem::path &data, bool loopbackOnly, const Log &log);

    // Packed publisher patch manifests carry an RSA-PSS signature by the server
    // that published them; a client trusts only its own server's key. Re-sign
    // zero-entry manifests whose signature this server's key does not verify.
    void signPatchManifests(const std::filesystem::path &data, const Log &log);
} // namespace content_pack
