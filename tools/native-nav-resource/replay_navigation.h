#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace iw8::navigation
{
    using Vec3 = std::array<float, 3>;
    inline constexpr std::uint32_t kBlocksMovement = 1u, kBlocksSight = 2u;

    struct Hull
    {
        std::vector<Vec3> points;
        std::uint32_t flags{};
        float nativeMargin{};
    };

    struct Triangle
    {
        std::array<Vec3, 3> corners{};
        std::uint32_t flags{};
    };

    struct Source
    {
        bool conservativeSurface{};
        std::vector<Hull> hulls;
        std::vector<Triangle> triangles;
        std::vector<Vec3> pathNodes, spawns;
    };

    std::vector<std::uint8_t> BuildResource(const Source &);
    std::string AuditResource(const Source &, const std::vector<std::uint8_t> &);
    std::string AuditSource(const Source &);
} // namespace iw8::navigation
