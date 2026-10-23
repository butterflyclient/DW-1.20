#include "zonetool/dumpsrc/xmodel_dump.h"
#include "zonetool/dumpsrc/xse_dump.h"
#include "zonetool/convert/conv_xsurface.h"
#include "zonetool/convert/xsurface_convert.h"
#include "zonetool/iw8/write_xsurface.h"
#include "zonetool/iw8/replay_render.h"
#include "common/ff_io.h"
#include "common/fs_util.h"
#include "common/json.hpp"
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>

using Json = nlohmann::json;
namespace fs = std::filesystem;

static std::vector<uint8_t> unhex(const std::string &text)
{
    if (text.size() % 2) throw std::runtime_error("Odd hex data");
    std::vector<uint8_t> out;
    for (size_t i = 0; i < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}

static void writeZone(iw8::ZoneWriter &writer, const fs::path &path)
{
    writer.build();
    zt::Iw8WriteParams params;
    for (unsigned i = 0; i < 11; ++i) params.blockSize[i] = writer.blockSize(i);
    params.totalDecompressed = writer.totalDecompressed();
    params.calcSize = writer.calcSize();
    if (!zt::iw8_write(path.string(), writer.body(), params))
        throw std::runtime_error("Failed writing fastfile");
    auto raw = path; raw.replace_extension(".raw");
    std::ofstream rawFile(raw, std::ios::binary);
    rawFile.write(reinterpret_cast<const char *>(writer.body().data()), writer.body().size());
    Json report{{"asset_count", writer.assetCount()}, {"body_bytes", writer.body().size()},
                {"calc_bytes", params.calcSize}, {"assets", Json::array()}};
    report["block_sizes"] = params.blockSize;
    for (const auto &[type, name] : writer.assetList())
        report["assets"].push_back({{"type", static_cast<unsigned>(type)}, {"name", name}});
    auto proof = path; proof.replace_extension(".writer.json");
    std::ofstream(proof) << report.dump(2) << '\n';
}

static replayrender::Material material(const Json &j, const fs::path &directory)
{
    replayrender::Material m;
    m.material = j.at("name"); m.techset = j.at("techset");
    m.materialInfo = unhex(j.at("info"));
    if (m.materialInfo.size() != 32) throw std::runtime_error("Native material info must be 32 bytes");
    m.constants = unhex(j.value("constants", std::string{}));
    m.bufferIndices = unhex(j.value("bufferIndices", std::string{}));
    for (const auto &buffer : j.value("buffers", Json::array()))
    {
        std::array<std::vector<uint8_t>, 4> stages;
        for (unsigned i = 0; i < 4; ++i) stages[i] = unhex(buffer.at(i));
        m.buffers.push_back(std::move(stages));
    }
    for (const auto &texture : j.at("textures"))
    {
        auto h = unhex(texture.at("header"));
        if (h.size() != 8) throw std::runtime_error("Texture header must be eight bytes");
        m.textureHeaders.insert(m.textureHeaders.end(), h.begin(), h.end());
        m.images.push_back(texture.at("image"));
    }
    if (m.materialInfo[20] != m.images.size() || m.materialInfo[21] * 20 != m.constants.size())
        throw std::runtime_error("Native material texture/constant counts disagree");
    for (const auto &source : j.at("images"))
    {
        replayrender::Image image;
        image.name = source.at("name"); image.width = source.at("width");
        image.height = source.at("height"); image.format = source.value("format", 7u);
        image.semantic = source.value("semantic", 1u);
        const auto pixels = directory / source.at("pixels").get<std::string>();
        std::ifstream stream(pixels, std::ios::binary | std::ios::ate);
        if (!stream) throw std::runtime_error("Cannot read image " + pixels.string());
        const auto length = static_cast<size_t>(stream.tellg());
        if (image.format != 7 || length != size_t(image.width) * image.height * 4)
            throw std::runtime_error("Expected resident RGBA8 image");
        image.pixels.resize((length + 15) & ~size_t{15});
        stream.seekg(0); stream.read(reinterpret_cast<char *>(image.pixels.data()), length);
        m.imageDefinitions.push_back(std::move(image));
    }
    return m;
}

int main(int argc, char **argv)
{
    try
    {
        if (argc != 3) throw std::runtime_error("Usage: custom-operator-model.exe input.json output.ff");
        const fs::path input = argv[1], output = argv[2];
        Json source; std::ifstream(input) >> source;
        if (source.at("schema") != 1) throw std::runtime_error("Unsupported operator schema");
        replayrender::Mesh materials;
        for (const auto &j : source.at("materials"))
            materials.assetMaterials.push_back(material(j, input.parent_path()));
        iw8::ZoneWriter writer;
        replayrender::RegisterMaterial(writer, materials);
        for (const auto &model : source.at("models"))
        {
            const auto physics = model.value("physicsAssetName", std::string{});
            if (!physics.empty() && !writer.has(ASSET_TYPE_PHYSICSASSET, physics))
                iw8::writePhysicsAssetReference(writer, physics);
        }
        for (const auto &model : source.at("models"))
        {
            convert::xmodel::Iw8XModelRecord rec;
            rec.name = model.at("name"); rec.numLods = 1; rec.collLod = 255;
            rec.shadowCutoffLod = 6; rec.boneNames = model.at("boneNames").get<std::vector<std::string>>();
            rec.contents = 1; rec.physicsAssetName = model.value("physicsAssetName", std::string{});
            const unsigned regularBones = model.at("numBones");
            const unsigned clientBones = model.at("numClientBones");
            if (!regularBones || regularBones > 254 || regularBones + clientBones > 768 ||
                rec.boneNames.size() != regularBones + clientBones)
                throw std::runtime_error("Invalid native regular/client bone counts");
            rec.numBones = static_cast<uint8_t>(regularBones);
            rec.numClientBones = static_cast<uint16_t>(clientBones);
            rec.numRootBones = model.at("numRootBones");
            const auto &sk = model.at("skeleton");
            rec.skeleton.parentList = sk.at("parentList").get<std::vector<uint8_t>>();
            rec.skeleton.quats = sk.at("quats").get<std::vector<std::array<int16_t,4>>>();
            rec.skeleton.trans = sk.at("trans").get<std::vector<std::array<float,3>>>();
            rec.skeleton.partClassification = sk.at("partClassification").get<std::vector<uint8_t>>();
            for (const auto &b : sk.at("baseMat"))
                rec.skeleton.baseMat.push_back({b.at("quat").get<std::array<float,4>>(),
                    b.at("trans").get<std::array<float,3>>(), b.at("transWeight").get<float>()});
            for (const auto &b : sk.at("boneInfo"))
                rec.skeleton.boneInfo.push_back({b.at("midPoint").get<std::array<float,3>>(),
                    b.at("halfSize").get<std::array<float,3>>(), b.at("radiusSquared").get<float>()});
            const auto middle = model.at("skinBounds").at("midPoint").get<std::array<float,3>>();
            const auto half = model.at("skinBounds").at("halfSize").get<std::array<float,3>>();
            conv_xsurf::SkinBounds skinBounds;
            for (unsigned i = 0; i < 3; ++i)
            { rec.boundsMid[i] = skinBounds.mid[i] = middle[i]; rec.boundsHalf[i] = skinBounds.half[i] = half[i]; }
            rec.radius = std::sqrt(rec.boundsHalf[0]*rec.boundsHalf[0]+rec.boundsHalf[1]*rec.boundsHalf[1]+rec.boundsHalf[2]*rec.boundsHalf[2]);
            dumpsrc::XseFile xse; xse.loaded = true; xse.name = rec.name + "_surfs";
            for (const auto &mesh : model.at("surfaces"))
            {
                dumpsrc::XseSurface surf; surf.deformed = 1;
                // Resident character assets do not pass through transient
                // surface replacement. Their model header must already report
                // the weighted surfaces used by native DObj skinning.
                rec.flags |= 0x40000u;
                const auto counts = mesh.at("blendCounts").get<std::array<int16_t,4>>();
                std::copy(counts.begin(), counts.end(), surf.vertBlendCounts);
                surf.vertsBlend = mesh.at("blendWords").get<std::vector<uint16_t>>();
                for (const auto &v : mesh.at("vertices"))
                {
                    dumpsrc::XseVertex vertex;
                    for (unsigned i=0; i<3; ++i) vertex.xyz[i]=v.at("position").at(i);
                    vertex.binormalSign=v.value("sign", 1.f); vertex.color=0xFFFFFFFFu;
                    const auto uv=v.at("uv").get<std::array<float,2>>();
                    vertex.texCoord=(uint32_t(xsurf_conv::floatToHalf(uv[0]))<<16)|xsurf_conv::floatToHalf(uv[1]);
                    const auto packVec = [](const Json &a) {
                        uint32_t packed=0xFF000000u;
                        for (unsigned i=0;i<3;++i) packed |= uint32_t(std::clamp(std::lround(a.at(i).get<float>()*127.f+127.f),0l,254l))<<(i*8);
                        return packed;
                    };
                    vertex.normal=packVec(v.at("normal")); vertex.tangent=packVec(v.at("tangent"));
                    surf.verticies.push_back(vertex);
                }
                surf.triIndices=mesh.at("indices").get<std::vector<uint16_t>>();
                const auto bits=mesh.at("partBits").get<std::array<uint32_t,8>>();
                for (unsigned i=0;i<6;++i) { surf.partBits[i]=static_cast<int32_t>(bits[i]); xse.modelSurfPartBits[i]|=surf.partBits[i]; }
                surf.vertCount=static_cast<uint32_t>(surf.verticies.size()); surf.triCount=static_cast<uint32_t>(surf.triIndices.size()/3);
                rec.materials.push_back(mesh.at("material")); xse.surfaces.push_back(std::move(surf));
            }
            rec.numsurfs=static_cast<uint16_t>(xse.surfaces.size()); rec.himipRadiusInvSq.assign(rec.numsurfs,0.f);
            convert::xmodel::Iw8LodInfo lod; lod.dist=1000000.f; lod.numsurfs=rec.numsurfs; lod.surfsName=xse.name;
            for(unsigned i=0;i<6;++i) lod.partBits[i]=static_cast<uint32_t>(xse.modelSurfPartBits[i]);
            rec.lods.push_back(lod);
            auto surfaces=conv_xsurf::convert(xse, &skinBounds);
            if(!surfaces.ok) throw std::runtime_error("No model surfaces");
            // XSE has only six mask words. Restore the complete Replay mask,
            // including bit 254 requesting client-bone animation evaluation.
            for (size_t index = 0; index < surfaces.surfaces.size(); ++index)
            {
                const auto bits=model.at("surfaces").at(index).at("partBits").get<std::array<uint32_t,8>>();
                for (unsigned word = 0; word < 8; ++word)
                {
                    surfaces.surfaces[index].partBits[word] = bits[word];
                    surfaces.partBits[word] |= bits[word];
                    rec.lods[0].partBits[word] |= bits[word];
                }
            }
            iw8xs_dump::writeXModelSurfs(writer,xse.name,surfaces); iw8::writeXModel(writer,rec);
        }
        fs::create_directories(output.parent_path()); writeZone(writer,output);
        iw8::ZoneWriter empty; auto companion=output.parent_path()/"empty.ff"; writeZone(empty,companion);
        return 0;
    }
    catch(const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
}
