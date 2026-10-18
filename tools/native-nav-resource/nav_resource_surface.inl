// Standalone conservative refinement. The original serializer remains unchanged.
// Sample every cell center, edge midpoint and corner before polygon merging.
// Keep cells only where the standing-cylinder audit can agree with source Scene.
struct SurfaceRefinementStats
{
    std::size_t removedCells{};
    std::size_t omittedPortalPairs{};
    std::size_t reachableCells{};
    std::size_t unmappedSpawns{};
};
SurfaceRefinementStats surfaceRefinementStats;

void ConstrainSurface(const Scene &scene, const Source &source, Grid &grid)
{
    surfaceRefinementStats = {};
    constexpr float supportTolerance = 0.25f;
    constexpr unsigned radialSamples = 16;
    std::vector<Span> spans;
    std::size_t removed = 0;
    for (std::uint32_t cell = 0; cell < grid.layers.size(); ++cell)
    {
        if (!grid.kept[cell])
            continue;
        const Vec3 center = grid.Center(cell);
        bool valid = true;
        for (int dy = -1; dy <= 1 && valid; ++dy)
            for (int dx = -1; dx <= 1 && valid; ++dx)
            {
                const float x = center[0] + dx * grid.cell * 0.5f;
                const float y = center[1] + dy * grid.cell * 0.5f;
                const float z = grid.HeightAt(cell, x, y);
                float error = kInfinity;
                for (const Layer &floor : ColumnFloors(scene, x, y, spans))
                    error = std::min(error, std::abs(floor.z - z));
                if (error > supportTolerance)
                {
                    valid = false;
                    break;
                }
                for (unsigned radial = 0; radial < radialSamples && valid; ++radial)
                {
                    const float angle = radial * 6.28318530718f / radialSamples;
                    const float px = x + kAgentRadius * std::cos(angle);
                    const float py = y + kAgentRadius * std::sin(angle);
                    scene.Column(px, py, spans);
                    for (const Span &span : spans)
                        if (span.hi > z + 1.0f && span.lo < z + kAgentHeight)
                            valid = false;
                    for (const float height : {1.0f, kAgentHeight * 0.5f,
                                               kAgentHeight - 0.25f})
                        if (scene.Blocked({x, y, z + height},
                                          {px, py, z + height}, kBlocksMovement))
                            valid = false;
                }
            }
        if (!valid)
        {
            grid.kept[cell] = 0;
            ++removed;
        }
    }
    // Shared mesh corners may only join source planes agreeing at both portal
    // ends. An 18-unit traversable step is not a license to average its floors.
    for (std::uint32_t cell = 0; cell < grid.layers.size(); ++cell)
        for (int direction = 0; direction < 4; ++direction)
        {
            const auto other = grid.Next(cell, direction);
            if (!grid.kept[cell] || other < 0)
                continue;
            const Vec3 center = grid.Center(cell);
            const float x = center[0] + kDirX[direction] * grid.cell * 0.5f;
            const float y = center[1] + kDirY[direction] * grid.cell * 0.5f;
            bool agreement = true;
            for (const float side : {-0.5f, 0.5f})
            {
                const float px = x + (direction & 1 ? side * grid.cell : 0);
                const float py = y + (direction & 1 ? 0 : side * grid.cell);
                agreement = agreement &&
                    std::abs(grid.HeightAt(cell, px, py) -
                             grid.HeightAt(other, px, py)) <= supportTolerance;
            }
            if (!agreement)
            {
                ++surfaceRefinementStats.omittedPortalPairs;
                grid.neighbor[cell * 4 + direction] = -1;
                grid.neighbor[std::size_t(other) * 4 + ((direction + 2) & 3)] = -1;
            }
        }
    std::vector<std::uint8_t> reached(grid.layers.size(), 0);
    std::vector<std::uint32_t> queue;
    for (const Vec3 &spawn : source.spawns)
    {
        const auto cell = Locate(grid, spawn, 96.0f, 40.0f, 6);
        if (cell >= 0 && !reached[cell])
        {
            reached[cell] = 1;
            queue.push_back(cell);
        }
        if (cell < 0)
            ++surfaceRefinementStats.unmappedSpawns;
    }
    for (std::size_t head = 0; head < queue.size(); ++head)
        for (int direction = 0; direction < 4; ++direction)
        {
            const auto cell = grid.Next(queue[head], direction);
            if (cell >= 0 && !reached[cell])
            {
                reached[cell] = 1;
                queue.push_back(cell);
            }
        }
    for (std::size_t cell = 0; cell < grid.kept.size(); ++cell)
        grid.kept[cell] = grid.kept[cell] && reached[cell];
    zt::info("navigation: conservative source-surface refinement removed %zu cells; %zu seed-reachable remain",
             removed, queue.size());
    surfaceRefinementStats.removedCells = removed;
    surfaceRefinementStats.reachableCells = queue.size();
}
