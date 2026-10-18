#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// Windows types are included explicitly below. Keep generated COM headers from
// pulling ole2.h and its automatic uuid.lib linker directives into this native
// image object; interface UUIDs are supplied by __uuidof/IID_PPV_ARGS.
#define COM_NO_WINDOWS_H
#include <windows.h>
#include <combaseapi.h>
#define __ocidl_h__ // D3D12 uses IUnknown, not the unrelated OLE control interfaces.
#include "SV_HostBotGpu.h"
#include "SV_HostBotGpuShader.h"
#include <d3d12.h>
#include <dxgi1_4.h>
#include <string.h>

namespace HostBotGpu
{
namespace
{
constexpr uint32_t RingSize = 3;
constexpr uint64_t NodeBytes = sizeof(Node) * MaxNodes;
constexpr uint64_t EdgeBytes = sizeof(Edge) * MaxEdges;
constexpr uint64_t RequestBytes = sizeof(Request) * MaxBots;
constexpr uint64_t InputBytes = NodeBytes + EdgeBytes + RequestBytes;
constexpr uint64_t OutputBytes = sizeof(Result) * MaxBots;
struct Batch
{
    ID3D12CommandAllocator *allocator;
    ID3D12GraphicsCommandList *commands;
    ID3D12Resource *input, *output, *readback;
    ID3D12QueryHeap *timestamps;
    void *mapped;
    uint64_t fence, started;
    uint32_t count;
};
ID3D12Device *device;
ID3D12CommandQueue *queue;
ID3D12Fence *fence;
ID3D12RootSignature *root;
ID3D12PipelineState *pipeline;
Batch batches[RingSize];
Config configuration;
Metrics metrics;
uint64_t sequence;
bool initialized;
// One cached System32 module reference for process lifetime; retries never add
// more references. This uses existing kernel32 imports, not new game PE IATs.
HMODULE d3d12Module;
decltype(&D3D12CreateDevice) createDevice;
decltype(&D3D12SerializeRootSignature) serializeRootSignature;
bool ResolveD3D12()
{
    if (!d3d12Module)
        d3d12Module = LoadLibraryExW(L"d3d12.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!d3d12Module)
    {
        metrics.lastError = HRESULT_FROM_WIN32(GetLastError());
        return false;
    }
    createDevice =
        reinterpret_cast<decltype(createDevice)>(GetProcAddress(d3d12Module, "D3D12CreateDevice"));
    serializeRootSignature = reinterpret_cast<decltype(serializeRootSignature)>(
        GetProcAddress(d3d12Module, "D3D12SerializeRootSignature"));
    if (!createDevice || !serializeRootSignature)
    {
        metrics.lastError = E_NOINTERFACE;
        return false;
    }
    return true;
}

template <class T> void Release(T *&object)
{
    if (object)
    {
        object->Release();
        object = nullptr;
    }
}
bool Check(HRESULT result)
{
    if (SUCCEEDED(result))
        return true;
    metrics.lastError = result;
    ++metrics.deviceFailures;
    metrics.enabled = 0;
    return false;
}
void ReleaseAll()
{
    for (auto &batch : batches)
    {
        if (batch.mapped)
        {
            batch.input->Unmap(0, nullptr);
            batch.mapped = nullptr;
        }
        Release(batch.commands);
        Release(batch.allocator);
        Release(batch.input);
        Release(batch.output);
        Release(batch.readback);
        Release(batch.timestamps);
        batch.fence = 0;
    }
    Release(pipeline);
    Release(root);
    Release(fence);
    Release(queue);
    Release(device);
    initialized = false;
}
bool Buffer(ID3D12Resource **resource, uint64_t bytes, D3D12_HEAP_TYPE heap,
            D3D12_RESOURCE_STATES state, D3D12_RESOURCE_FLAGS flags)
{
    D3D12_HEAP_PROPERTIES properties = {};
    properties.Type = heap;
    properties.CreationNodeMask = properties.VisibleNodeMask = 1;
    D3D12_RESOURCE_DESC description = {};
    description.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    description.Width = bytes;
    description.Height = description.DepthOrArraySize = description.MipLevels = 1;
    description.SampleDesc.Count = 1;
    description.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    description.Flags = flags;
    return Check(device->CreateCommittedResource(&properties, D3D12_HEAP_FLAG_NONE, &description,
                                                 state, nullptr, IID_PPV_ARGS(resource)));
}
void Transition(Batch &batch, D3D12_RESOURCE_STATES before, D3D12_RESOURCE_STATES after)
{
    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = batch.output;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = before;
    barrier.Transition.StateAfter = after;
    batch.commands->ResourceBarrier(1, &barrier);
}
bool Valid(const Graph &graph, const Request *requests, uint32_t count)
{
    if (!graph.nodes || !graph.edges || !requests || !count || count > MaxBots ||
        !graph.nodeCount || graph.nodeCount > MaxNodes || graph.edgeCount > MaxEdges)
        return false;
    for (uint32_t n = 0; n < graph.nodeCount; ++n)
    {
        const Node &node = graph.nodes[n];
        if (node.firstEdge > graph.edgeCount || node.edgeCount > graph.edgeCount - node.firstEdge)
            return false;
    }
    for (uint32_t e = 0; e < graph.edgeCount; ++e)
        if (graph.edges[e].destination >= graph.nodeCount || !(graph.edges[e].cost >= 0.0f) ||
            graph.edges[e].cost > 1.0e20f)
            return false;
    for (uint32_t r = 0; r < count; ++r)
        if (requests[r].slot >= MaxBots || requests[r].startNode >= graph.nodeCount ||
            requests[r].goalNode >= graph.nodeCount)
            return false;
    return true;
}
} // namespace

bool Initialize(const Config &config)
{
    // Never replace a live queue or abandon resources to reinitialize repeatedly.
    if (initialized || device)
        return metrics.enabled != 0;
    if (!ResolveD3D12())
        return false;
    configuration = config;
    if (!(configuration.lookAheadCost >= 0.0f) || configuration.lookAheadCost > 1.0e20f)
        configuration.lookAheadCost = 0.0f;
    if (!configuration.maxExpansions || configuration.maxExpansions > MaxNodes)
        configuration.maxExpansions = 128;
    if (!configuration.timeoutMs)
        configuration.timeoutMs = 500;
    IDXGIFactory4 *factory = nullptr;
    if (!Check(CreateDXGIFactory1(IID_PPV_ARGS(&factory))))
        return false;
    IDXGIAdapter1 *selected = nullptr;
    for (UINT index = 0;; ++index)
    {
        IDXGIAdapter1 *adapter = nullptr;
        if (factory->EnumAdapters1(index, &adapter) == DXGI_ERROR_NOT_FOUND)
            break;
        if (!adapter)
            break;
        DXGI_ADAPTER_DESC1 description = {};
        HRESULT result = adapter->GetDesc1(&description);
        bool exact = description.AdapterLuid.LowPart == config.adapterLuidLow &&
                     description.AdapterLuid.HighPart == config.adapterLuidHigh;
        if (SUCCEEDED(result) && !(description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) &&
            (exact || config.allowAnyHardwareAdapter) &&
            SUCCEEDED(createDevice(adapter, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device))))
        {
            metrics.adapterVendor = description.VendorId;
            metrics.adapterDevice = description.DeviceId;
            metrics.adapterLuidLow = description.AdapterLuid.LowPart;
            metrics.adapterLuidHigh = description.AdapterLuid.HighPart;
            selected = adapter;
            break;
        }
        adapter->Release();
    }
    factory->Release();
    if (!selected)
    {
        metrics.lastError = DXGI_ERROR_NOT_FOUND;
        return false;
    }
    selected->Release();
    D3D12_COMMAND_QUEUE_DESC queueDescription = {};
    queueDescription.Type = D3D12_COMMAND_LIST_TYPE_COMPUTE;
    if (!Check(device->CreateCommandQueue(&queueDescription, IID_PPV_ARGS(&queue))) ||
        !Check(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence))))
    {
        ReleaseAll();
        return false;
    }
    if (!Check(queue->GetTimestampFrequency(&metrics.gpuTimestampFrequency)))
    {
        ReleaseAll();
        return false;
    }
    D3D12_ROOT_PARAMETER parameters[5] = {};
    parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
    parameters[0].Constants.Num32BitValues = 6;
    for (UINT p = 1; p < 5; ++p)
    {
        parameters[p].ParameterType =
            p == 4 ? D3D12_ROOT_PARAMETER_TYPE_UAV : D3D12_ROOT_PARAMETER_TYPE_SRV;
        parameters[p].Descriptor.ShaderRegister = p == 4 ? 0 : p - 1;
    }
    D3D12_ROOT_SIGNATURE_DESC signature = {};
    signature.NumParameters = 5;
    signature.pParameters = parameters;
    ID3DBlob *serialized = nullptr, *errors = nullptr;
    HRESULT result =
        serializeRootSignature(&signature, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors);
    Release(errors);
    if (!Check(result))
    {
        Release(serialized);
        ReleaseAll();
        return false;
    }
    result = device->CreateRootSignature(0, serialized->GetBufferPointer(),
                                         serialized->GetBufferSize(), IID_PPV_ARGS(&root));
    serialized->Release();
    if (!Check(result))
    {
        ReleaseAll();
        return false;
    }
    D3D12_COMPUTE_PIPELINE_STATE_DESC state = {};
    state.pRootSignature = root;
    state.CS.pShaderBytecode = HostBotGpuShader;
    state.CS.BytecodeLength = sizeof(HostBotGpuShader);
    if (!Check(device->CreateComputePipelineState(&state, IID_PPV_ARGS(&pipeline))))
    {
        ReleaseAll();
        return false;
    }
    for (auto &batch : batches)
    {
        if (!Check(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_COMPUTE,
                                                  IID_PPV_ARGS(&batch.allocator))) ||
            !Check(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_COMPUTE, batch.allocator,
                                             pipeline, IID_PPV_ARGS(&batch.commands))) ||
            !Check(batch.commands->Close()) ||
            !Buffer(&batch.input, InputBytes, D3D12_HEAP_TYPE_UPLOAD,
                    D3D12_RESOURCE_STATE_GENERIC_READ, D3D12_RESOURCE_FLAG_NONE) ||
            !Buffer(&batch.output, OutputBytes, D3D12_HEAP_TYPE_DEFAULT,
                    D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
                    D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS) ||
            !Buffer(&batch.readback, OutputBytes + 2 * sizeof(uint64_t), D3D12_HEAP_TYPE_READBACK,
                    D3D12_RESOURCE_STATE_COPY_DEST, D3D12_RESOURCE_FLAG_NONE))
        {
            ReleaseAll();
            return false;
        }
        D3D12_QUERY_HEAP_DESC queryDescription = {};
        queryDescription.Type = D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
        queryDescription.Count = 2;
        if (!Check(device->CreateQueryHeap(&queryDescription, IID_PPV_ARGS(&batch.timestamps))))
        {
            ReleaseAll();
            return false;
        }
        D3D12_RANGE empty = {0, 0};
        if (!Check(batch.input->Map(0, &empty, &batch.mapped)))
        {
            ReleaseAll();
            return false;
        }
    }
    initialized = true;
    metrics.enabled = 1;
    return true;
}

bool Submit(const Graph &graph, const Request *requests, uint32_t count)
{
    if (!metrics.enabled)
        return false;
    if (!Valid(graph, requests, count))
    {
        ++metrics.invalid;
        return false;
    }
    Batch *available = nullptr;
    for (auto &batch : batches)
        if (!batch.fence)
        {
            available = &batch;
            break;
        }
    if (!available)
    {
        ++metrics.busy;
        return false;
    }
    Batch &batch = *available;
    memcpy(batch.mapped, graph.nodes, graph.nodeCount * sizeof(Node));
    memcpy(static_cast<uint8_t *>(batch.mapped) + NodeBytes, graph.edges,
           graph.edgeCount * sizeof(Edge));
    memcpy(static_cast<uint8_t *>(batch.mapped) + NodeBytes + EdgeBytes, requests,
           count * sizeof(Request));
    if (!Check(batch.allocator->Reset()) ||
        !Check(batch.commands->Reset(batch.allocator, pipeline)))
        return false;
    batch.commands->SetComputeRootSignature(root);
    uint32_t constants[] = {
        graph.nodeCount, graph.edgeCount, count, graph.version, configuration.maxExpansions, 0};
    memcpy(&constants[5], &configuration.lookAheadCost, sizeof(float));
    batch.commands->SetComputeRoot32BitConstants(0, 6, constants, 0);
    auto address = batch.input->GetGPUVirtualAddress();
    batch.commands->SetComputeRootShaderResourceView(1, address);
    batch.commands->SetComputeRootShaderResourceView(2, address + NodeBytes);
    batch.commands->SetComputeRootShaderResourceView(3, address + NodeBytes + EdgeBytes);
    batch.commands->SetComputeRootUnorderedAccessView(4, batch.output->GetGPUVirtualAddress());
    batch.commands->EndQuery(batch.timestamps, D3D12_QUERY_TYPE_TIMESTAMP, 0);
    batch.commands->Dispatch(count, 1, 1);
    batch.commands->EndQuery(batch.timestamps, D3D12_QUERY_TYPE_TIMESTAMP, 1);
    Transition(batch, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_COPY_SOURCE);
    batch.commands->CopyBufferRegion(batch.readback, 0, batch.output, 0, count * sizeof(Result));
    batch.commands->ResolveQueryData(batch.timestamps, D3D12_QUERY_TYPE_TIMESTAMP, 0, 2,
                                     batch.readback, OutputBytes);
    Transition(batch, D3D12_RESOURCE_STATE_COPY_SOURCE, D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
    if (!Check(batch.commands->Close()))
        return false;
    ID3D12CommandList *lists[] = {batch.commands};
    batch.fence = ++sequence;
    batch.started = GetTickCount64();
    batch.count = count;
    queue->ExecuteCommandLists(1, lists);
    ++metrics.pending;
    if (!Check(queue->Signal(fence, batch.fence)))
        return false;
    ++metrics.submitted;
    return true;
}

uint32_t Poll(Result *results, uint32_t capacity)
{
    if (!initialized)
        return 0;
    uint64_t complete = fence->GetCompletedValue();
    if (complete == UINT64_MAX)
    {
        Check(device->GetDeviceRemovedReason());
        metrics.enabled = 0;
        metrics.pending = 0;
        ReleaseAll();
        return 0;
    }
    uint32_t written = 0;
    for (auto &batch : batches)
    {
        if (!batch.fence)
            continue;
        if (complete < batch.fence)
        {
            if (metrics.enabled && GetTickCount64() - batch.started > configuration.timeoutMs)
            {
                ++metrics.timeouts;
                metrics.enabled = 0;
            }
            continue;
        }
        if (metrics.enabled && results && batch.count <= capacity - written)
        {
            D3D12_RANGE range = {0, OutputBytes + 2 * sizeof(uint64_t)};
            void *data = nullptr;
            if (Check(batch.readback->Map(0, &range, &data)))
            {
                memcpy(results + written, data, batch.count * sizeof(Result));
                written += batch.count;
                const auto *ticks = reinterpret_cast<const uint64_t *>(
                    static_cast<const uint8_t *>(data) + OutputBytes);
                if (ticks[1] >= ticks[0] && metrics.gpuTimestampFrequency)
                {
                    metrics.lastGpuMicroseconds =
                        (ticks[1] - ticks[0]) * 1000000 / metrics.gpuTimestampFrequency;
                    if (metrics.lastGpuMicroseconds > metrics.maxGpuMicroseconds)
                        metrics.maxGpuMicroseconds = metrics.lastGpuMicroseconds;
                }
                D3D12_RANGE empty = {0, 0};
                batch.readback->Unmap(0, &empty);
            }
        }
        else if (metrics.enabled && results)
            continue; // caller supplies >= MaxBots.
        batch.fence = 0;
        --metrics.pending;
        ++metrics.completed;
    }
    if (!metrics.enabled && !metrics.pending)
        ReleaseAll();
    return written;
}
Metrics GetMetrics()
{
    return metrics;
}
void Disable()
{
    metrics.enabled = 0;
}
static_assert(sizeof(Node) == 24 && sizeof(Edge) == 12 && sizeof(Request) == 24 &&
                  sizeof(Result) == 32,
              "CPU/HLSL structured buffer layout mismatch");
} // namespace HostBotGpu
