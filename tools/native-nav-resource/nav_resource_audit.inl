// Independent adapter logic; retained generator and Scene implementation stay unchanged.
#include <sstream>
#include <iomanip>

namespace iw8::navigation
{
    std::string AuditSource(const Source &source)
    {
        const Scene scene(source);
        std::vector<Span> spans;
        std::ostringstream result;
        result << std::setprecision(9)
               << "{\"method\":\"source Scene authored-spawn floor coverage\","
               << "\"native_runtime_validation\":false,\"spawn_results\":[";
        unsigned found = 0;
        for (std::size_t index = 0; index < source.spawns.size(); ++index)
        {
            const Vec3 &spawn = source.spawns[index];
            auto floors = ColumnFloors(scene, spawn[0], spawn[1], spans);
            float error = kInfinity, floor = 0;
            for (const Layer &candidate : floors)
                if (std::abs(candidate.z - spawn[2]) < error)
                {
                    error = std::abs(candidate.z - spawn[2]);
                    floor = candidate.z;
                }
            const bool covered = std::isfinite(error) && floor >= spawn[2] - 96.0f &&
                                 floor <= spawn[2] + 40.0f;
            found += covered;
            if (index)
                result << ',';
            result << "{\"spawn\":[" << spawn[0] << ',' << spawn[1] << ',' << spawn[2]
                   << "],\"walkable_floor_count\":" << floors.size()
                   << ",\"within_generator_seed_height\":" << (covered ? "true" : "false")
                   << ",\"nearest_floor\":";
            if (std::isfinite(error))
                result << floor;
            else
                result << "null";
            result << ",\"vertical_gap\":";
            if (std::isfinite(error))
                result << error;
            else
                result << "null";
            result << ",\"source_column_spans\":[";
            for (std::size_t spanIndex = 0; spanIndex < spans.size(); ++spanIndex)
            {
                const Span &span = spans[spanIndex];
                if (spanIndex)
                    result << ',';
                result << "{\"minimum_z\":" << span.lo
                       << ",\"maximum_z\":" << span.hi
                       << ",\"top_normal_z\":" << span.topNormal[2] << '}';
            }
            result << "]}";
        }
        result << "],\"covered_spawns\":" << found << ",\"total_spawns\":" << source.spawns.size()
               << '}';
        return result.str();
    }

    std::string AuditResource(const Source &source, const std::vector<std::uint8_t> &resource)
    {
        const Scene scene(source);
        constexpr float heightTolerance = 2.0f;
        constexpr unsigned circleSamples = 16;
        unsigned points = 0, heightFailures = 0, clearanceFailures = 0;
        unsigned centerSamples = 0, edgeSamples = 0, interiorSamples = 0;
        unsigned spawnSamples = 0, spawnUncovered = 0;
        float maxHeightError = 0;
        std::ostringstream failures;
        unsigned retainedFailures = 0;
        auto number = [&](std::size_t at)
        {
            std::uint32_t value;
            std::memcpy(&value, resource.data() + at, sizeof(value));
            return value;
        };
        auto pointAt = [&](std::size_t at)
        {
            Vec3 point;
            std::memcpy(point.data(), resource.data() + at, sizeof(point));
            return point;
        };
        std::vector<Span> spans;
        auto auditPoint = [&](const Vec3 &point, const char *kind, bool checkSupport)
        {
            ++points;
            bool heightBad = false, clearanceBad = false;
            float nearestError = kInfinity;
            scene.Column(point[0], point[1], spans);
            for (const Span &span : spans)
                if (span.topNormal[2] >= kMinFloorNormal)
                    nearestError = std::min(nearestError, std::abs(span.hi - point[2]));
            if (checkSupport)
            {
                heightBad = nearestError > heightTolerance;
                if (std::isfinite(nearestError))
                    maxHeightError = std::max(maxHeightError, nearestError);
            }
            // Discrete standing cylinder probes, not a native continuous capsule sweep.
            for (unsigned sample = 0; sample <= circleSamples; ++sample)
            {
                const float angle = float(sample) * 6.28318530718f / circleSamples;
                const float radius = sample == circleSamples ? 0.0f : kAgentRadius;
                const float x = point[0] + radius * std::cos(angle);
                const float y = point[1] + radius * std::sin(angle);
                scene.Column(x, y, spans);
                for (const Span &span : spans)
                    if (span.hi > point[2] + heightTolerance && span.lo < point[2] + kAgentHeight)
                        clearanceBad = true;
                if (radius != 0)
                    for (const float height :
                         {heightTolerance, kAgentHeight * 0.5f, kAgentHeight - 0.25f})
                        if (scene.Blocked({point[0], point[1], point[2] + height},
                                          {x, y, point[2] + height},
                                          kBlocksMovement))
                            clearanceBad = true;
            }
            heightFailures += heightBad;
            clearanceFailures += clearanceBad;
            if ((heightBad || clearanceBad) && retainedFailures < 64)
            {
                if (retainedFailures++)
                    failures << ',';
                failures << "{\"kind\":\"" << kind << "\",\"position\":[" << point[0] << ','
                         << point[1] << ',' << point[2] << "],\"height_error\":";
                if (std::isfinite(nearestError))
                    failures << nearestError;
                else
                    failures << "null";
                failures << ",\"height_failed\":" << (heightBad ? "true" : "false")
                         << ",\"clearance_failed\":" << (clearanceBad ? "true" : "false") << '}';
            }
        };
        const std::size_t base = 48;
        const std::size_t areaEnd = 340 + number(base + 8);

        struct Polygon
        {
            std::vector<Vec3> vertices;
        };

        std::vector<Polygon> polygons;
        for (std::size_t at = 340; at < areaEnd;)
        {
            const unsigned count = number(base + at + 56) & 127u;
            Polygon polygon;
            for (unsigned edge = 0; edge < count; ++edge)
                polygon.vertices.push_back(pointAt(base + at + 80 + edge * 32));
            const Vec3 center = pointAt(base + at + 32);
            ++centerSamples;
            auditPoint(center, "area_center", true);
            for (unsigned edge = 0; edge < count; ++edge)
            {
                const Vec3 &a = polygon.vertices[edge];
                const Vec3 &b = polygon.vertices[(edge + 1) % count];
                Vec3 midpoint = Scale(Add(a, b), 0.5f);
                ++edgeSamples;
                auditPoint(midpoint, "edge_midpoint", true);
                // Interior fan barycenters exercise polygon surfaces, not just boundaries.
                ++interiorSamples;
                auditPoint(Scale(Add(Add(center, a), b), 1.0f / 3.0f), "interior_fan", true);
            }
            polygons.push_back(std::move(polygon));
            at += 72 + count * 32;
        }
        for (const Vec3 &spawn : source.spawns)
        {
            ++spawnSamples;
            bool covered = false;
            Vec3 closest{};
            float closestHeight = kInfinity;
            for (const Polygon &polygon : polygons)
            {
                bool inside = true;
                for (std::size_t edge = 0; edge < polygon.vertices.size(); ++edge)
                {
                    const auto &a = polygon.vertices[edge];
                    const auto &b = polygon.vertices[(edge + 1) % polygon.vertices.size()];
                    if ((b[0] - a[0]) * (spawn[1] - a[1]) - (b[1] - a[1]) * (spawn[0] - a[0]) <
                        -0.01f)
                        inside = false;
                }
                if (!inside)
                    continue;
                const auto &a = polygon.vertices[0];
                Vec3 normal{};
                for (std::size_t vertex = 2; vertex < polygon.vertices.size(); ++vertex)
                {
                    normal = Cross(Sub(polygon.vertices[1], a), Sub(polygon.vertices[vertex], a));
                    if (std::abs(normal[2]) >= 0.001f)
                        break;
                }
                if (std::abs(normal[2]) < 0.001f)
                    continue;
                const float z =
                    a[2] -
                    (normal[0] * (spawn[0] - a[0]) + normal[1] * (spawn[1] - a[1])) / normal[2];
                const float error = std::abs(z - spawn[2]);
                if (error < closestHeight)
                {
                    closestHeight = error;
                    closest = {spawn[0], spawn[1], z};
                    covered =
                        error <= 40.0f; // matches original generator spawn seed vertical allowance
                }
            }
            if (!covered)
                ++spawnUncovered;
            else
                auditPoint(closest, "spawn_projected_surface", true);
        }
        std::ostringstream report;
        report << std::setprecision(9)
               << "{\"method\":\"retained Scene discrete column and radial ray sampling\","
               << "\"continuous_native_capsule_sweep\":false,\"complete_surface_coverage\":false,"
               << "\"agent_radius\":" << kAgentRadius << ",\"agent_height\":" << kAgentHeight
               << ",\"agent_step_height\":" << kStepHeight
               << ",\"conservative_surface_refinement\":" << (source.conservativeSurface ? "true" : "false")
               << ",\"removed_unsafe_cells\":" << surfaceRefinementStats.removedCells
               << ",\"omitted_mismatching_plane_portal_pairs\":" << surfaceRefinementStats.omittedPortalPairs
               << ",\"refined_seed_reachable_cells\":" << surfaceRefinementStats.reachableCells
               << ",\"refinement_unmapped_spawns\":" << surfaceRefinementStats.unmappedSpawns
               << ",\"height_tolerance\":" << heightTolerance
               << ",\"circumference_probes_per_point\":" << circleSamples
               << ",\"sample_points\":" << points << ",\"area_centers\":" << centerSamples
               << ",\"edge_midpoints\":" << edgeSamples
               << ",\"interior_fan_samples\":" << interiorSamples
               << ",\"spawn_seeds\":" << spawnSamples << ",\"uncovered_spawns\":" << spawnUncovered
               << ",\"height_failures\":" << heightFailures
               << ",\"clearance_failures\":" << clearanceFailures
               << ",\"maximum_sampled_height_error\":" << maxHeightError
               << ",\"sampled_checks_passed\":"
               << (!(heightFailures || clearanceFailures || spawnUncovered) ? "true" : "false")
               << ",\"failure_examples\":[" << failures.str() << "]}";
        return report.str();
    }
} // namespace iw8::navigation
