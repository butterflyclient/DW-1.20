#include <d3d12.h>
#include <dxgi1_4.h>
#include <wrl/client.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>

using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;

static void check(HRESULT hr, const char *operation)
{
    if (FAILED(hr)) throw std::runtime_error(std::string(operation)+": "+std::to_string(unsigned(hr)));
}

static std::vector<char> read(const fs::path &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open "+path.string());
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

static ComPtr<ID3D12Resource> buffer(ID3D12Device *device, UINT64 bytes,
    D3D12_HEAP_TYPE type, D3D12_RESOURCE_STATES state, D3D12_RESOURCE_FLAGS flags = D3D12_RESOURCE_FLAG_NONE)
{
    D3D12_HEAP_PROPERTIES heap{}; heap.Type=type;
    heap.CreationNodeMask=heap.VisibleNodeMask=1;
    D3D12_RESOURCE_DESC desc{}; desc.Dimension=D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width=bytes; desc.Height=desc.DepthOrArraySize=desc.MipLevels=1;
    desc.SampleDesc.Count=1; desc.Layout=D3D12_TEXTURE_LAYOUT_ROW_MAJOR; desc.Flags=flags;
    ComPtr<ID3D12Resource> resource;
    check(device->CreateCommittedResource(&heap,D3D12_HEAP_FLAG_NONE,&desc,state,nullptr,
        IID_PPV_ARGS(&resource)),"Create buffer");
    return resource;
}

int wmain(int argc, wchar_t **argv)
{
    try
    {
        if (argc!=4) throw std::runtime_error("Usage: operator_gpu_skin_harness shader.cso fixture-directory output.bin");
        const fs::path fixture=argv[2];
        const auto shader=read(argv[1]);
        auto groupsBytes=read(fixture/L"t5.bin");
        if (groupsBytes.empty() || groupsBytes.size()%8) throw std::runtime_error("Invalid workgroups");
        ComPtr<IDXGIFactory4> factory;
        check(CreateDXGIFactory1(IID_PPV_ARGS(&factory)),"Create factory");
        ComPtr<IDXGIAdapter1> adapter;
        check(factory->EnumAdapters1(0,&adapter),"Select adapter");
        DXGI_ADAPTER_DESC1 adapterDesc{};
        check(adapter->GetDesc1(&adapterDesc),"Read adapter");
        ComPtr<ID3D12Device> device;
        check(D3D12CreateDevice(adapter.Get(),D3D_FEATURE_LEVEL_11_0,IID_PPV_ARGS(&device)),"Create device");
        D3D12_DESCRIPTOR_RANGE ranges[2]{};
        ranges[0].RangeType=D3D12_DESCRIPTOR_RANGE_TYPE_SRV; ranges[0].NumDescriptors=7;
        ranges[1].RangeType=D3D12_DESCRIPTOR_RANGE_TYPE_UAV; ranges[1].NumDescriptors=1;
        D3D12_ROOT_PARAMETER params[2]{};
        for(unsigned i=0;i<2;++i) {
            params[i].ParameterType=D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
            params[i].DescriptorTable.NumDescriptorRanges=1;
            params[i].DescriptorTable.pDescriptorRanges=&ranges[i];
        }
        D3D12_ROOT_SIGNATURE_DESC rootDesc{};rootDesc.NumParameters=2;rootDesc.pParameters=params;
        ComPtr<ID3DBlob> rootBlob,errors;
        check(D3D12SerializeRootSignature(&rootDesc,D3D_ROOT_SIGNATURE_VERSION_1,&rootBlob,&errors),"Serialize root");
        ComPtr<ID3D12RootSignature> root;
        check(device->CreateRootSignature(0,rootBlob->GetBufferPointer(),rootBlob->GetBufferSize(),IID_PPV_ARGS(&root)),"Create root");
        D3D12_COMPUTE_PIPELINE_STATE_DESC pipelineDesc{};
        pipelineDesc.pRootSignature=root.Get();pipelineDesc.CS={shader.data(),shader.size()};
        ComPtr<ID3D12PipelineState> pipeline;
        check(device->CreateComputePipelineState(&pipelineDesc,IID_PPV_ARGS(&pipeline)),"Create pipeline");
        D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
        heapDesc.Type=D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;heapDesc.NumDescriptors=8;
        heapDesc.Flags=D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        ComPtr<ID3D12DescriptorHeap> heap;
        check(device->CreateDescriptorHeap(&heapDesc,IID_PPV_ARGS(&heap)),"Create descriptors");
        const auto stride=device->GetDescriptorHandleIncrementSize(heapDesc.Type);
        auto cpu=heap->GetCPUDescriptorHandleForHeapStart();
        std::array<ComPtr<ID3D12Resource>,7> inputs;
        for(unsigned i=0;i<7;++i) {
            auto data=read(fixture/(L"t"+std::to_wstring(i)+L".bin"));
            if(data.empty() || data.size()%4) throw std::runtime_error("Invalid input buffer");
            inputs[i]=buffer(device.Get(),data.size(),D3D12_HEAP_TYPE_UPLOAD,D3D12_RESOURCE_STATE_GENERIC_READ);
            void *mapped{};D3D12_RANGE noRead{0,0};
            check(inputs[i]->Map(0,&noRead,&mapped),"Map upload");
            memcpy(mapped,data.data(),data.size());inputs[i]->Unmap(0,nullptr);
            D3D12_SHADER_RESOURCE_VIEW_DESC view{};
            view.Shader4ComponentMapping=D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
            view.ViewDimension=D3D12_SRV_DIMENSION_BUFFER;
            if(i==4) {
                view.Format=DXGI_FORMAT_UNKNOWN;view.Buffer.StructureByteStride=32;
                view.Buffer.NumElements=unsigned(data.size()/32);
            } else {
                view.Format=DXGI_FORMAT_R32_TYPELESS;view.Buffer.Flags=D3D12_BUFFER_SRV_FLAG_RAW;
                view.Buffer.NumElements=unsigned(data.size()/4);
            }
            device->CreateShaderResourceView(inputs[i].Get(),&view,cpu);cpu.ptr+=stride;
        }
        constexpr UINT64 outputBytes=0xd00000;
        auto output=buffer(device.Get(),outputBytes,D3D12_HEAP_TYPE_DEFAULT,
            D3D12_RESOURCE_STATE_UNORDERED_ACCESS,D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS);
        auto readback=buffer(device.Get(),outputBytes,D3D12_HEAP_TYPE_READBACK,D3D12_RESOURCE_STATE_COPY_DEST);
        D3D12_UNORDERED_ACCESS_VIEW_DESC uav{};uav.Format=DXGI_FORMAT_R32_TYPELESS;
        uav.ViewDimension=D3D12_UAV_DIMENSION_BUFFER;uav.Buffer.NumElements=outputBytes/4;
        uav.Buffer.Flags=D3D12_BUFFER_UAV_FLAG_RAW;
        device->CreateUnorderedAccessView(output.Get(),nullptr,&uav,cpu);
        ComPtr<ID3D12CommandQueue> queue;D3D12_COMMAND_QUEUE_DESC queueDesc{};
        check(device->CreateCommandQueue(&queueDesc,IID_PPV_ARGS(&queue)),"Create queue");
        ComPtr<ID3D12CommandAllocator> allocator;
        check(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,IID_PPV_ARGS(&allocator)),"Create allocator");
        ComPtr<ID3D12GraphicsCommandList> commands;
        check(device->CreateCommandList(0,D3D12_COMMAND_LIST_TYPE_DIRECT,allocator.Get(),pipeline.Get(),IID_PPV_ARGS(&commands)),"Create commands");
        ID3D12DescriptorHeap *heaps[]={heap.Get()};commands->SetDescriptorHeaps(1,heaps);
        commands->SetComputeRootSignature(root.Get());
        auto gpu=heap->GetGPUDescriptorHandleForHeapStart();
        commands->SetComputeRootDescriptorTable(0,gpu);gpu.ptr+=7*stride;
        commands->SetComputeRootDescriptorTable(1,gpu);
        commands->Dispatch(unsigned(groupsBytes.size()/8),1,1);
        D3D12_RESOURCE_BARRIER barrier{};barrier.Type=D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource=output.Get();barrier.Transition.Subresource=D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore=D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
        barrier.Transition.StateAfter=D3D12_RESOURCE_STATE_COPY_SOURCE;
        commands->ResourceBarrier(1,&barrier);
        commands->CopyBufferRegion(readback.Get(),0,output.Get(),0,outputBytes);
        check(commands->Close(),"Close commands");
        ID3D12CommandList *lists[]={commands.Get()};queue->ExecuteCommandLists(1,lists);
        ComPtr<ID3D12Fence> fence;check(device->CreateFence(0,D3D12_FENCE_FLAG_NONE,IID_PPV_ARGS(&fence)),"Create fence");
        HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
        if(!event) throw std::runtime_error("Create event failed");
        check(queue->Signal(fence.Get(),1),"Signal fence");
        check(fence->SetEventOnCompletion(1,event),"Fence event");
        const DWORD waited=WaitForSingleObject(event,10000);CloseHandle(event);
        if(waited!=WAIT_OBJECT_0) throw std::runtime_error("GPU dispatch timed out");
        check(device->GetDeviceRemovedReason(),"GPU dispatch");
        void *mapped{};D3D12_RANGE range{0,outputBytes};
        check(readback->Map(0,&range,&mapped),"Map readback");
        std::ofstream file(argv[3],std::ios::binary);file.write(static_cast<char *>(mapped),outputBytes);
        D3D12_RANGE noWrite{0,0};readback->Unmap(0,&noWrite);
        std::wcout<<L"PASS: original skinning shader dispatched on "<<adapterDesc.Description<<L"\n";
        return 0;
    }
    catch(const std::exception &e) { std::cerr<<e.what()<<'\n';return 1; }
}
