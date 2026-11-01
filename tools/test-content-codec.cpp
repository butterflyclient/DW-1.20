#include "../src/playlist_compression.h"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

int main(int argc, char** argv)
{
    try
    {
        const auto rejects = [](const wire::Bytes& data)
        {
            try { (void)content_pack::compressPlaylist(data); }
            catch (const std::runtime_error&) { return true; }
            return false;
        };
        if (!rejects({}) || !rejects(wire::Bytes(content_pack::playlistDecodedCapacity)) ||
            !rejects(wire::Bytes(content_pack::playlistDecodedCapacity + 1)))
            throw std::runtime_error("Decoded size bounds not enforced");
        const wire::Bytes largest(content_pack::playlistDecodedCapacity - 1, 'x');
        if (content_pack::compressPlaylist(largest).empty())
            throw std::runtime_error("Maximum terminated decoded size was rejected");
        wire::Bytes random(content_pack::playlistDecodedCapacity - 1);
        uint32_t generator = 0x12345678;
        for (auto& byte : random)
        {
            generator ^= generator << 13; generator ^= generator >> 17; generator ^= generator << 5;
            byte = static_cast<uint8_t>(generator);
        }
        if (!rejects(random)) throw std::runtime_error("Oversized compressed publication accepted");
        if (argc != 3) throw std::runtime_error("Provide decoded playlist JSON and compressed output path");
        std::ifstream input(argv[1], std::ios::binary);
        const wire::Bytes plain((std::istreambuf_iterator<char>(input)), {});
        const auto packed = content_pack::compressPlaylist(plain);
        std::ofstream output(argv[2], std::ios::binary);
        output.write(reinterpret_cast<const char*>(packed.data()), packed.size());
        if (!output) throw std::runtime_error("Cannot write compressed evidence");
        std::printf("PASS: bounded native playlist compression %zu -> %zu bytes; empty/oversized/incompressible inputs rejected\n",
            plain.size(), packed.size());
        return 0;
    }
    catch (const std::exception& error) { std::printf("FAIL: %s\n", error.what()); return 1; }
}
