#include "playlist_compression.h"
#include <miniz.h>
#include <stdexcept>

namespace content_pack
{
    wire::Bytes compressPlaylist(std::span<const uint8_t> data)
    {
        if (data.empty() || data.size() >= playlistDecodedCapacity)
            throw std::runtime_error("Playlist exceeds native decoded capacity");
        wire::Bytes out(playlistCompressedCapacity);
        mz_ulong size = static_cast<mz_ulong>(out.size());
        const auto result = mz_compress2(out.data(), &size, data.data(),
            static_cast<mz_ulong>(data.size()), MZ_BEST_COMPRESSION);
        if (result != MZ_OK || !size || size > playlistCompressedCapacity)
            throw std::runtime_error("Playlist cannot fit native compressed download capacity");
        out.resize(size);
        return out;
    }
}
