// Execute the production selector against isolated catalog/package publications.
// This executable contains no game image, network listener or platform identity.
#include "../src/playlist_catalog.h"
#include <fstream>
#include <iostream>

int main(int argc, char **argv)
{
    using Json = nlohmann::json;
    if (argc != 2)
        return 2;
    try
    {
        const std::filesystem::path directory(argv[1]);
        std::ifstream input(directory / "playlists/5800/catalog.json");
        const auto catalog = Json::parse(input);
        Json result = Json::array();
        for (const auto &playlist : catalog.at("playlists"))
        {
            const auto id = playlist.at("playlist").get<unsigned>();
            Json query = {{"ruleset_payload",
                           {{"filter", {{"playlist_id", id},
                                        {"playlist_version", catalog.at("system").at("version")}}}}}};
            const auto selected = services::selectPlaylist(directory, 5800, query);
            if (selected)
                result.push_back({{"playlist", id}, {"team_count", selected->teamCount},
                                  {"rules", selected->rules}, {"metadata", selected->metadata}});
            else
                result.push_back({{"playlist", id}, {"unavailable", true}});
        }
        std::cout << result.dump() << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Playlist contract rejected: " << error.what() << '\n';
        return 1;
    }
}
