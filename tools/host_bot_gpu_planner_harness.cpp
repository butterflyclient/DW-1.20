// Compiles the actual frozen coordinator; only external engine/GPU boundaries
// are modeled. This is coordinator correctness evidence, not hardware evidence.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SV_HostBotGpuPlanner.cpp"
namespace Fixture {
bool mainThread, ready, scaleEnabled=true, submitAllowed=true;
dvar_t *toggleDvar;
unsigned initialized, captures, submits, submittedCount;
HostBotGpu::Request requests[200]; HostBotGpu::Result results[600]; unsigned resultCount;
HostBotGpu::Node copiedNodes[2048]; HostBotGpu::Edge copiedEdges[16384];
uint32_t copiedVersion;
HostBotGpu::Metrics metrics{};
float waypointX=600;
void *areas[3]={reinterpret_cast<void *>(0x1100),reinterpret_cast<void *>(0x2200),reinterpret_cast<void *>(0x3300)};
alignas(16) unsigned char space[160]{};
HostScale::NavAreaHandle start{&areas[0],space},goal{&areas[2],space};
HostScale::NavSearchSpec spec{};
HostScale::Vec3 origin{}, destination{1200,0,0};
void Require(bool value,const char *message) { if (!value) { printf("FAIL %s\n",message); exit(1); } }
const void *Owner(unsigned slot) { return reinterpret_cast<void *>(uintptr_t(0x10000+slot)); }
const void *Player(unsigned slot) { return reinterpret_cast<void *>(uintptr_t(0x20000+slot)); }
const void *Nav(unsigned slot) { return reinterpret_cast<void *>(uintptr_t(0x30000+slot)); }
bool Queue(unsigned slot) { return HostBotPlanner::Queue(slot,Owner(slot),Player(slot),Nav(slot),77,start,goal,spec,origin,destination); }
HostBotPlanner::RouteState Take(unsigned slot) { HostScale::Vec3 output{}; auto state=HostBotPlanner::Take(slot,Owner(slot),Player(slot),Nav(slot),77,start,origin,output); if(state==HostBotPlanner::RouteState::Ready) Require(output.x==600,"copied graph waypoint"); return state; }
void Complete(HostBotGpu::Status status=HostBotGpu::Route,unsigned waypoint=1) {
    resultCount=submittedCount;
    for(unsigned i=0;i<resultCount;++i) { const auto &r=requests[i]; results[i]={r.slot,r.generation,r.tick,copiedVersion,waypoint,status,1200,3,2}; }
    ready=true;
}
}
extern "C" {
int32_t SVHS_LevelTime=100;
int32_t SVHS_FrameDuration=50;
uint32_t SVHS_ClientCount=200;
void *SVHS_GameStatics=reinterpret_cast<void *>(0x90000);
bool Sys_IsMainThread() { return Fixture::mainThread; }
void Com_Printf(int,const char *,...) {}
void Cmd_AddCommandInternal(const char *,void (*)(),cmd_function_s *) {}
void Dvar_BeginPermanentRegistration() {}
void Dvar_EndPermanentRegistration() {}
dvar_t *Dvar_RegisterBool(const char *,bool value,uint32_t,const char *) { static dvar_t var{};var.current.enabled=value;Fixture::toggleDvar=&var;return &var; }
void SV_HostBot_ResetGasState() {}
bool SV_HostBot_GetGasState(HostScale::BotGasState *) { return false; }
}
namespace HostScale {
bool Enabled() { return Fixture::scaleEnabled; }
uint64_t Clock() { static uint64_t value;return ++value; }
NavGraphResult GatherNavGraph(const NavAreaHandle &start,const NavAreaHandle &goal,const NavSearchSpec &spec,uint64_t epoch,NavGraphSnapshot &out,uint32_t,uint32_t) {
    ++Fixture::captures; out={};out.epoch=epoch;out.spaceIdentity=uint64_t(reinterpret_cast<uintptr_t>(start.space));out.specification=spec;
    out.nodeCount=3;out.edgeCount=2;out.startNode=0;out.goalNode=2;
    for(unsigned n=0;n<3;++n) out.nodes[n]={{n==1?Fixture::waypointX:float(n)*600,0,0},n<2?n:2,n<2?1u:0u,uint64_t(reinterpret_cast<uintptr_t>(Fixture::areas[n]))};
    out.edges[0]={1,600,{300,0,0}};out.edges[1]={2,600,{900,0,0}};
    (void)goal;return NavGraphResult::Ready;
}
uint32_t FindNavGraphNode(const NavGraphSnapshot &graph,const NavAreaHandle &area,uint64_t epoch) {
    if(graph.epoch!=epoch || graph.spaceIdentity!=uint64_t(reinterpret_cast<uintptr_t>(area.space))) return ~0u;
    for(unsigned i=0;i<graph.nodeCount;++i) if(graph.nodes[i].areaIdentity==uint64_t(reinterpret_cast<uintptr_t>(*area.reference)))return i;
    return ~0u;
}
}
namespace HostBotGpu {
bool Initialize(const Config &) { ++Fixture::initialized;Fixture::metrics.enabled=1;return true; }
bool Submit(const Graph &graph,const Request *requests,uint32_t count) {
    ++Fixture::submits;if(!Fixture::submitAllowed)return false;
    Fixture::submittedCount=count;Fixture::copiedVersion=graph.version;
    memcpy(Fixture::requests,requests,count*sizeof(Request));
    memcpy(Fixture::copiedNodes,graph.nodes,graph.nodeCount*sizeof(Node));memcpy(Fixture::copiedEdges,graph.edges,graph.edgeCount*sizeof(Edge));return true;
}
uint32_t Poll(Result *out,uint32_t capacity) { if(!Fixture::ready)return 0;Fixture::Require(capacity>=Fixture::resultCount,"poll capacity");memcpy(out,Fixture::results,Fixture::resultCount*sizeof(Result));Fixture::ready=false;return Fixture::resultCount; }
Metrics GetMetrics() { return Fixture::metrics; }
void Disable() { Fixture::metrics.enabled=0; }
}
int main() {
    using namespace Fixture; using HostBotPlanner::RouteState;
    HostBotPlanner::Frame();Require(initialized==0,"wrong-owner frontend does not initialize");
    mainThread=true;HostBotPlanner::Frame();mainThread=false;Require(initialized==1,"frontend initialization");
    HostBotPlanner::BeginServerFrame(true);
    Require(!HostBotPlanner::Queue(30,Owner(30),Player(30),Nav(30),77,start,start,spec,origin,destination),"same polygon native fallback");
    Require(captures==0 && !HostBotPlanner::Pending(30),"same polygon avoids graph capture and pending slot");
    for(unsigned i=0;i<200;++i) Require(Queue(i),"queue all200 same frame");
    Require(captures==1,"same graph captured once");
    waypointX=999;HostBotPlanner::EndServerFrame();waypointX=600;
    Require(submits==1 && submittedCount==200,"one batch for200 same-frame requests");
    Require(copiedNodes[1].x==600 && copiedEdges[0].cost==600,"copied native graph values");
    Require(Take(0)==RouteState::Pending,"pending route");Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    for(unsigned i=0;i<200;++i) Require(Take(i)==RouteState::Ready,"200 matching identities commit");
    Require(!Queue(200),"human/out-of-range slot excluded");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    const HostScale::Vec3 exactA{1100,50,0},exactB{1250,-75,0};
    Require(HostBotPlanner::Queue(20,Owner(20),Player(20),Nav(20),77,start,goal,spec,origin,exactA),"queue exact goal A");
    Require(HostBotPlanner::Queue(21,Owner(21),Player(21),Nav(21),77,start,goal,spec,origin,exactB),"queue exact goal B same polygon");
    HostBotPlanner::EndServerFrame();Require(submittedCount==2,"same goal polygon batches distinct destinations");Complete(HostBotGpu::Route,2);
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);HostScale::Vec3 exactOutput{};
    Require(HostBotPlanner::Take(20,Owner(20),Player(20),Nav(20),77,start,origin,exactOutput)==RouteState::Ready && !memcmp(&exactOutput,&exactA,sizeof(exactA)),"goal node preserves exact destination A");
    Require(HostBotPlanner::Take(21,Owner(21),Player(21),Nav(21),77,start,origin,exactOutput)==RouteState::Ready && !memcmp(&exactOutput,&exactB,sizeof(exactB)),"goal node preserves exact destination B");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(0),"queue wrong owner case");HostBotPlanner::EndServerFrame();Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    HostScale::Vec3 output{};Require(HostBotPlanner::Take(0,Owner(1),Player(0),Nav(0),77,start,origin,output)==RouteState::Fallback,"wrong owner rejected");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(1),"queue expired");HostBotPlanner::EndServerFrame();Complete();SVHS_LevelTime+=501;HostBotPlanner::BeginServerFrame(true);Require(Take(1)==RouteState::Fallback,"expired completion rejected");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(2),"queue map change");HostBotPlanner::EndServerFrame();Complete();SVHS_GameStatics=reinterpret_cast<void *>(0x91000);++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Take(2)==RouteState::Fallback,"old map completion rejected");
    Require(Queue(3),"queue budget");HostBotPlanner::EndServerFrame();Complete(HostBotGpu::BudgetExceeded);++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Take(3)==RouteState::Fallback && !Queue(3),"budget fallback cooldown");
    SVHS_LevelTime+=1001;HostBotPlanner::BeginServerFrame(true);Require(Queue(3),"cooldown permits retry");HostBotPlanner::Cancel(3);HostBotPlanner::EndServerFrame();Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Take(3)==RouteState::Fallback,"cancel generation rejects old result");
    // Keep one settled ready slot and one submitted pending slot across an
    // explicit off frame. Re-enabling must never revive either old command.
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(10),"queue dvar-ready case");HostBotPlanner::EndServerFrame();Complete();
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(HostBotPlanner::Pending(10),"ready slot retained before disable");
    Require(Queue(11),"queue dvar-pending case");HostBotPlanner::EndServerFrame();
    toggleDvar->current.enabled=false;
    Require(!HostBotPlanner::Pending(10) && !HostBotPlanner::Pending(11),"disabled Pending must hide ready and in-flight states");
    Require(Take(10)==RouteState::Fallback,"disabled Take falls back and cancels ready command");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    toggleDvar->current.enabled=true;
    Require(Take(10)==RouteState::Fallback && Take(11)==RouteState::Fallback,"reenable must not revive old ready/pending commands");
    Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    Require(Take(11)==RouteState::Fallback,"late completion after reenable must remain canceled");
    Require(Queue(12),"reenable allows fresh planning");HostBotPlanner::Cancel(12);HostBotPlanner::EndServerFrame();Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(13),"queue submission-failure case");
    submitAllowed=false;HostBotPlanner::EndServerFrame();submitAllowed=true;
    Require(Take(13)==RouteState::Fallback && !Queue(13),"failed submission native fallback cooldown");
    SVHS_LevelTime+=999;HostBotPlanner::BeginServerFrame(true);Require(!Queue(13),"failed submission cooldown lasts1000ms");
    ++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(Queue(13),"failed submission permits fresh retry after1000ms");
    HostBotPlanner::Cancel(13);HostBotPlanner::EndServerFrame();Complete();++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);
    metrics.enabled=0;++SVHS_LevelTime;HostBotPlanner::BeginServerFrame(true);Require(!HostBotPlanner::Enabled() && !Queue(4),"device disable native fallback");
    puts("PASS actual coordinator:200same-frame batch/copied graph/identity/expired/map/budget cooldown/same-polygon fallback/exact per-bot goal/submission-failure cooldown/cancel/dvar off-on no stale command/device fallback/frontend owner");
    puts("LIMIT human in-range bot ownership belongs to native caller; this fixture checks only coordinator slot bound");return 0;
}
