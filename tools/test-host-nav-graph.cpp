#include "../integration/host-scale/SV_HostNavGraph.h"
#include <assert.h>
#include <string.h>
#include <chrono>
#include <stdio.h>
using namespace HostScale;
template<class T> void Put(void *p,unsigned o,T v){memcpy(static_cast<uint8_t *>(p)+o,&v,sizeof(v));}
int main()
{
    alignas(8) uint8_t a[256]={}, b[256]={}, space[160]={};
    float matrix[16]={1,0,0,0,0,1,0,0,0,0,1,0,100,200,300,1};
    memcpy(space+76,matrix,sizeof(matrix));
    Put(a,56,3u); Put(b,56,3u);
    Put(a,32,Vec3{0,0,0}); Put(b,32,Vec3{10,0,0});
    Put(a,72,b); Put(b,72,a);
    Put(a,80,Vec3{5,-2,0}); Put(a,112,Vec3{5,2,0}); Put(a,144,Vec3{-2,0,0});
    Put(b,80,Vec3{5,2,0}); Put(b,112,Vec3{5,-2,0}); Put(b,144,Vec3{12,0,0});
    void *ap=a,*bp=b;
    NavAreaHandle start{&ap,space}, goal{&bp,space}; NavSearchSpec spec{}; spec.areaFlags=~0u;
    static NavGraphSnapshot graph;
    assert(GatherNavGraph(start,goal,spec,123,graph)==NavGraphResult::Ready);
    assert(graph.nodeCount==2 && graph.edgeCount==2 && graph.goalNode==1);
    assert(graph.nodes[0].position.x==100 && graph.edges[0].portal.x==105 && graph.edges[0].cost==10);
    assert(FindNavGraphNode(graph,goal,123)==1);
    assert(FindNavGraphNode(graph,goal,124)==~0u);
    Put(space,76+12*4,101.0f);
    assert(FindNavGraphNode(graph,goal,123)==~0u);
    Put(space,76+12*4,100.0f);
    assert(GatherNavGraph(start,goal,spec,124,graph,1)==NavGraphResult::GoalOutsidePartition);
    assert(graph.clippedEdges==1 && graph.epoch==124);
    Put(b,16,a);
    assert(GatherNavGraph(start,goal,spec,125,graph)==NavGraphResult::UnsupportedArea);
    Put(b,16,static_cast<void *>(nullptr));
    uint32_t childCount=0; Put(b,8,&childCount);
    assert(GatherNavGraph(start,goal,spec,125,graph)==NavGraphResult::Ready);
    childCount=1;
    assert(GatherNavGraph(start,goal,spec,125,graph)==NavGraphResult::UnsupportedArea);
    Put(b,8,static_cast<void *>(nullptr)); Put(b,56,0x20000003u);
    assert(GatherNavGraph(start,goal,spec,125,graph)==NavGraphResult::UnsupportedArea);
    Put(b,56,3u); Put(b,52,6u); spec.areaFlags=2;
    assert(GatherNavGraph(start,goal,spec,126,graph)==NavGraphResult::Ready); // any matching usage bit
    spec.areaFlags=8;
    assert(GatherNavGraph(start,goal,spec,126,graph)==NavGraphResult::UnsupportedArea);

    // Representative capacity fixture, two directed links per interior area.
    alignas(8) static uint8_t mesh[NavGraphMaxNodes][256];
    for (unsigned i=0;i<NavGraphMaxNodes;++i)
    {
        Put(mesh[i],56,3u); Put(mesh[i],32,Vec3{float(i*10),0,0});
        for (unsigned e=0;e<3;++e) Put(mesh[i],80+32*e,Vec3{float(i*10),float(e),0});
        if (i) Put(mesh[i],72,mesh[i-1]);
        if (i+1<NavGraphMaxNodes) Put(mesh[i],104,mesh[i+1]);
    }
    void *first=mesh[0], *last=mesh[NavGraphMaxNodes-1];
    NavAreaHandle begin{&first,space}, end{&last,space}; spec.areaFlags=~0u;
    // Rotate 90 degrees around Z and translate; test transformed graph geometry.
    matrix[0]=0; matrix[1]=1; matrix[4]=-1; matrix[5]=0;
    memcpy(space+76,matrix,sizeof(matrix));
    auto before=std::chrono::steady_clock::now();
    assert(GatherNavGraph(begin,end,spec,200,graph)==NavGraphResult::Ready);
    auto after=std::chrono::steady_clock::now();
    assert(graph.nodeCount==2048 && graph.edgeCount==4094);
    assert(graph.nodes[2047].position.x==100 && graph.nodes[2047].position.y==20670);
    volatile unsigned checksum=0;
    auto linearStart=std::chrono::steady_clock::now();
    for(unsigned pass=0;pass<200;++pass)
        for(unsigned i=0;i<2048;++i)
        {
            unsigned j=0;
            while(graph.nodes[j].areaIdentity!=reinterpret_cast<uint64_t>(mesh[i])) ++j;
            checksum=checksum+j;
        }
    auto linearEnd=std::chrono::steady_clock::now();
    for(unsigned pass=0;pass<200;++pass)
        for(unsigned i=0;i<2048;++i)
        {
            void *p=mesh[i]; NavAreaHandle h{&p,space};
            unsigned found=FindNavGraphNode(graph,h,200); assert(found==i);
            checksum=checksum+found;
        }
    auto hashEnd=std::chrono::steady_clock::now();
    printf("2048 nodes/4094 edges: gather %lld us, 409600 linear lookups %lld us, hash lookups %lld us, checksum %u\n",
        (long long)std::chrono::duration_cast<std::chrono::microseconds>(after-before).count(),
        (long long)std::chrono::duration_cast<std::chrono::microseconds>(linearEnd-linearStart).count(),
        (long long)std::chrono::duration_cast<std::chrono::microseconds>(hashEnd-linearEnd).count(),unsigned(checksum));
    return 0;
}
