#pragma once
#include "wire.h"

namespace content_pack
{
    // Common native publisher-playlist contract. Version-specific publication
    // data stays separate; every emitted stream must fit these input/output
    // buffers before it can be advertised to a client.
    // Replay 1.20 passes 0xa000 to its native object download and 0x50000
    // to the zero-initialized inflate buffer. Leave its last byte available
    // for the native JSON parser's terminating zero.
    inline constexpr size_t playlistCompressedCapacity = 0xa000;
    inline constexpr size_t playlistDecodedCapacity = 0x50000;
    wire::Bytes compressPlaylist(std::span<const uint8_t> data);
}
