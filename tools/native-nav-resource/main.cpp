#include "replay_navigation.h"
#include <fstream>
#include <stdexcept>
#include <cstdio>
#include <cmath>
using namespace iw8::navigation;

namespace
{
    template <class T> T Read(std::istream &in)
    {
        T value{};
        if (!in.read(reinterpret_cast<char *>(&value), sizeof(value)))
            throw std::runtime_error("truncated geometry interchange");
        return value;
    }

    Vec3 Point(std::istream &in)
    {
        Vec3 p = Read<Vec3>(in);
        for (float x : p)
            if (!std::isfinite(x) || std::abs(x) > 10000000)
                throw std::runtime_error("invalid point");
        return p;
    }

    unsigned Count(std::istream &in, unsigned maximum)
    {
        unsigned n = Read<unsigned>(in);
        if (n > maximum)
            throw std::runtime_error("geometry count exceeds bound");
        return n;
    }
} // namespace

int main(int argc, char **argv)
{
    try
    {
        if (argc != 4 && argc != 5)
            throw std::runtime_error("usage: generator input.geom output.bfx audit.json");
        std::ifstream input(argv[1], std::ios::binary);
        if (Read<unsigned>(input) != 0x3247564e)
            throw std::runtime_error("bad geometry interchange magic");
        Source source;
        if (argc == 5)
        {
            if (std::string(argv[4]) != "--conservative-surface")
                throw std::runtime_error("unknown generator refinement option");
            source.conservativeSurface = true;
        }
        const unsigned hullCount = Count(input, 100000), triangleCount = Count(input, 2000000);
        const unsigned spawnCount = Count(input, 10000), nodeCount = Count(input, 10000);
        source.hulls.reserve(hullCount);
        source.triangles.reserve(triangleCount);
        for (unsigned i = 0; i < hullCount; ++i)
        {
            Hull h;
            h.flags = Read<unsigned>(input);
            const unsigned count = Count(input, 4096);
            h.nativeMargin = Read<float>(input);
            if (!std::isfinite(h.nativeMargin) || h.nativeMargin < 0 || h.nativeMargin > 128)
                throw std::runtime_error("invalid native convex margin");
            for (unsigned j = 0; j < count; ++j)
                h.points.push_back(Point(input));
            source.hulls.push_back(std::move(h));
        }
        for (unsigned i = 0; i < triangleCount; ++i)
        {
            Triangle t;
            t.flags = Read<unsigned>(input);
            for (auto &p : t.corners)
                p = Point(input);
            source.triangles.push_back(t);
        }
        for (unsigned i = 0; i < spawnCount; ++i)
            source.spawns.push_back(Point(input));
        for (unsigned i = 0; i < nodeCount; ++i)
            source.pathNodes.push_back(Point(input));
        if (input.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("trailing geometry data");
        if (std::string(argv[2]) == "--audit-source")
        {
            std::ofstream output(argv[3], std::ios::trunc);
            output << AuditSource(source) << '\n';
            if (!output)
                throw std::runtime_error("source audit write failed");
            return 0;
        }
        auto resource = BuildResource(source);
        if (resource.empty())
            throw std::runtime_error("no reachable walkable mesh generated");
        std::ofstream audit(argv[3], std::ios::trunc);
        audit << AuditResource(source, resource) << '\n';
        if (!audit)
            throw std::runtime_error("audit write failed");
        std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char *>(resource.data()), resource.size());
        if (!output)
            throw std::runtime_error("output write failed");
        return 0;
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
