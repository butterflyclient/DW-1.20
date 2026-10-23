"""Compile custom operator owner and check native boundaries offline."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
LLVM = Path(r"C:\Program Files\LLVM\bin")
HARNESS = r"""
#include <stdarg.h>
#include "DW_CustomOperators.cpp"
extern "C" {
alignas(8) uint8_t DW_Bot_CustomizationPackages[8192 * 40]{};
alignas(8) uint8_t DW_Bot_CustomizationGroups[3 * 16]{};
int DW_Bot_CustomizationEnabled = 1;
alignas(8) uint8_t CO_LocalCustomization[8 * 24]{};
static dvar_t option{};
static dvar_t readyOption{};
static unsigned refreshed, originalHead, originalBody, seenHead, seenBody, seenVariant;
static unsigned operatorZoneState = 2, globalStreamState = 2, commonMpState = 2;
unsigned DWBSZ_PollFastfileState(const char *name) {
 return *name == 'd' ? operatorZoneState : *name == 'g' ? globalStreamState : commonMpState;
}
void Dvar_BeginPermanentRegistration() {}
void Dvar_EndPermanentRegistration() {}
dvar_t *Dvar_RegisterInt(const char *, int, int, int, unsigned, const char *) { return &option; }
dvar_t *Dvar_RegisterBool(const char *, bool, unsigned, const char *) { return &readyOption; }
void Dvar_SetVariant(dvar_t *dvar, const DvarValue *value, int) { dvar->current = *value; }
void CO_Print(int, const char *, ...) {}
void DW_LocalBackend_LogLine(const char *) {}
static unsigned requestedCards, bindingsUpdated;
static bool bindResidentModels = true;
void CO_RequestCardUpload(unsigned) { ++requestedCards; }
bool CO_UploadCard(unsigned) { return true; }
void CO_UpdatePackageBindings(const char *) {
 ++bindingsUpdated;
 if (bindResidentModels)
  for(unsigned kind=0;kind<2;++kind)
   for(unsigned i=0;i<DWCustomOperators::Count;++i)
    reinterpret_cast<DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages)[s_packageSlots[kind][i]].invalid=0;
}
void *CO_GetLocalXuid(uint64_t *out, unsigned controller) { *out = controller ? 456 : 123; return out; }
int CO_Format(char *out, uint64_t size, const char *format, ...) {
 if (!size) return 0;
 out[0] = 0;
 if (*format != '%') return 0;
 va_list args; va_start(args, format); unsigned n = va_arg(args, unsigned); va_end(args);
 char backwards[16]{}; unsigned count=0; do { backwards[count++] = char('0'+n%10); n/=10; } while(n);
 unsigned i=0; while(i<count && i+1<size) {out[i]=backwards[count-i-1]; ++i;} out[i]=0; return int(i);
}
uint64_t CO_CardModelsNative(unsigned, uint8_t *faction, uint32_t *west, uint32_t *east, void *, void *) {
 *faction=1; west[0]=31; west[1]=49; west[2]=79; east[0]=32; east[1]=50; east[2]=80; return 95;
}
uint64_t CO_GetPlayercardNative(uint64_t, const char *, void *out) {
 auto *p = reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(out)+80);
 for(unsigned i=0;i<12;++i) p[i]=100+i;
 return 1;
}
uint32_t CO_TableHash(const char *text) { unsigned h=0; while(*text) h=h*31+unsigned(*text++); return h; }
int CO_TableRowNative(const void *asset, int column, const char *value) {
 auto *table=static_cast<const CO_StringTable *>(asset);
 if(column<0 || column>=table->columns) return -1;
 for(int row=table->rows-1;row>=0;--row) {
  unsigned cell=table->cells[row*table->columns+column];
  if(Equal(table->strings[cell],value)) return row;
 }
 return -1;
}
const char *CO_TableLookupNative(const void *asset, int comparison, const char *value, int column) {
 if(!asset) return "";
 const auto *table=static_cast<const CO_StringTable *>(asset);
 int row=CO_TableRowNative(asset,comparison,value);
 if(row<0 || column<0 || column>=table->columns) return "";
 return table->strings[table->cells[row*table->columns+column]];
}
void CO_UpdateLocalCustomization(unsigned controller) { refreshed += controller + 1; }
uint64_t CO_RegisterHeadsNative(const char *) { ++originalHead; return 17; }
uint64_t CO_RegisterBodiesNative(const char *) { ++originalBody; return 19; }
uint16_t CO_RegisterPackage(const char *model, const char *fallback, unsigned kind) {
 auto *g = reinterpret_cast<DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
 auto *p = reinterpret_cast<DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
 unsigned slot = g[kind].first + g[kind].count++;
 ++g[kind].maleCount;
 p[slot] = {model, fallback, 0, UINT16_MAX, UINT16_MAX, UINT16_MAX, 0, 0, UINT16_MAX, 1, 0, 0};
 return uint16_t(slot);
}
alignas(8) static uint8_t fakeEntities[0x5A0]{};
alignas(8) static uint8_t fakeClient[0x5700]{};
static uint8_t fakeGlobals[0x80]{};
uint8_t *CO_Entities = fakeEntities, *CO_ServerGlobals = fakeGlobals;
static bool fakeBot, remoteCustom;
static uint64_t entityXuid=123;
uint64_t CO_SetCustomizationNative(void *, uint64_t) {
 auto *out=reinterpret_cast<uint32_t *>(fakeClient+0x56D8); out[0]=11;out[1]=12;out[2]=13;return 97;
}
bool CO_IsBot(const void *) {return fakeBot;}
void *CO_ServerLobby() {return fakeEntities;}
uint64_t *CO_PartyXuid(uint64_t *out, const void *, int) {*out=entityXuid;return out;}
bool CO_CardSelections(uint64_t xuid,const char *,uint8_t *faction,uint32_t *west,uint32_t *east) {
 uint8_t card[128]{};DW_CustomOperators_GetPlayercard(xuid,"",card);*faction=0;
 auto *a=reinterpret_cast<uint32_t *>(card+80),*b=reinterpret_cast<uint32_t *>(card+104);
 for(unsigned i=0;i<3;++i) {west[i]=a[i];east[i]=b[i];}
 if(remoteCustom && xuid==456) west[0]=west[1]=east[0]=east[1]=60001;
 return true;
}
uint64_t CO_SetBody(void *out,unsigned body) {
 auto *p=static_cast<uint32_t *>(out);p[1]=body;p[2]=0;return 1;
}
uint64_t CO_SetHead(void *out,unsigned head) {static_cast<uint32_t *>(out)[0]=head;return 1;}
static CO_LocalPlayerView playerView{};
const uint8_t *CO_LocalClientGlobals[2]{reinterpret_cast<const uint8_t *>(&playerView),nullptr};
static bool forceModelFallback;
static bool missingBody;
const void *CO_DObjGetModel(const void *, unsigned) { return "stock_body_asset"; }
const void *CO_FindAsset(int kind, const char *name, int allowDefault) {
 return kind == 9 && !allowDefault && !missingBody ? name : nullptr;
}
bool CO_ShouldRecreateLegsNative(unsigned local, unsigned entity) { return local == 0 && entity == 7; }
void CO_UpdateLegsNative(unsigned, const void *) {}
const char *CO_GetActiveModelNative(unsigned,const void *,const void *,unsigned kind,bool *loaded) {
 *loaded=true;return kind==0?"stock_head":kind==1?"stock_body":"stock_hands";
}
int CO_GenerateActiveModel(unsigned,const char **out,const void *info,const void *,unsigned kind,int forceDefault) {
 auto *p=reinterpret_cast<DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
 auto *g=reinterpret_cast<DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
 auto *view=static_cast<const CO_ClientModelSelection *>(info);
 *out=p[g[kind].first+view->models[kind]].model;
 return (forceModelFallback || forceDefault)?1:0;
}
static const void *fakeTable;
const void *CO_GetTableNative(const char *,const void **out) {*out=fakeTable;return *out;}
int CO_TableMultiRowNative(const void *asset,const int *columns,const char *const *values,int count) {
 auto *table=static_cast<const CO_StringTable *>(asset);
 for(int row=table->rows-1;row>=0;--row) {
  bool match=true;
  for(int i=0;i<count;++i) if(columns[i]<0 || columns[i]>=table->columns ||
    !Equal(table->strings[table->cells[row*table->columns+columns[i]]],values[i])) match=false;
  if(match) return row;
 }
 return -1;
}
uint64_t CO_BuildCustomizationNative(void *, unsigned h, unsigned v, unsigned b, bool) {
 seenHead = h; seenBody = b; seenVariant = v; return 93;
}
__declspec(dllexport) int Test_Run() {
 #define CHECK(x) do { if (!(x)) return __LINE__; } while (false)
 auto *g = reinterpret_cast<DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
 auto *p = reinterpret_cast<DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
 g[0] = {0, 0, 2, 1, 1}; g[1] = {6143, 0, 2, 1, 1};
 p[6143].viewhands = 7167; p[6143].fallback="stock_body"; p[0].fallback="stock_head";
 CHECK(DW_CustomOperators_RegisterHeads("heads") == 17);
 CHECK(DW_CustomOperators_RegisterBodies("bodies") == 19);
 CHECK(originalHead == 1 && originalBody == 1);
 CHECK(g[0].count == 2 + DWCustomOperators::Count && g[1].count == 2 + DWCustomOperators::Count);
 CHECK(g[0].maleCount == 1 && g[0].femaleCount == 1 && g[1].maleCount == 1 && g[1].femaleCount == 1);
 for (unsigned i = 0; i < DWCustomOperators::Count; ++i) {
   CHECK(p[2+i].primary == 60000+i && p[6145+i].primary == 60000+i);
   CHECK(p[2+i].secondary == 0 && p[6145+i].secondary == UINT16_MAX);
   CHECK(Equal(p[2+i].fallback,"stock_head") && Equal(p[6145+i].fallback,"stock_body"));
   CHECK(!p[2+i].randomEligible && !p[6145+i].randomEligible);
   CHECK(p[6145+i].viewhands == 7167 && p[2+i].category == p[6145+i].category);
 }
 // Initial native binding can run before the custom zone is resident.
 for(unsigned i=0;i<DWCustomOperators::Count;++i) p[2+i].invalid=p[6145+i].invalid=1;
 operatorZoneState=1;
 DW_CustomOperators_ZoneInstalled(true);
 DW_CustomOperators_Frame();
 CHECK(bindingsUpdated == 0 && !ModelsReady());
 operatorZoneState=2;
 DW_CustomOperators_Frame();
 CHECK(bindingsUpdated == 1 && ModelsReady());
 DW_CustomOperators_Frame(); CHECK(bindingsUpdated == 1);
 bindResidentModels=false;
 unsigned remote[3]{};
 for (unsigned selected = 0; selected <= DWCustomOperators::Count; ++selected) {
   option.current.integer = int(selected);
   for (unsigned controller = 0; controller < 1; ++controller) {
     CHECK(DW_CustomOperators_BuildCustomization(CO_LocalCustomization + 24*controller, 31, 7, 49, false) == 93);
     CHECK(seenHead == 31);
     CHECK(seenBody == 49);
     CHECK(seenVariant == 7);
   }
   DW_CustomOperators_BuildCustomization(remote, 31, 7, 49, false);
   CHECK(seenHead == 31 && seenBody == 49 && seenVariant == 7);
   DW_CustomOperators_BuildCustomization(CO_LocalCustomization + 12, 31, 7, 49, false);
   CHECK(seenHead == 31 && seenBody == 49 && seenVariant == 7);
   DW_CustomOperators_BuildCustomization(CO_LocalCustomization + 8*24, 31, 7, 49, false);
   CHECK(seenHead == 31 && seenBody == 49 && seenVariant == 7);
   DW_CustomOperators_Frame(); unsigned before = refreshed;
   DW_CustomOperators_Frame(); CHECK(refreshed == before);
 }
 // The actual appearance paths use playercards and StringTable IDs, rather
 // than the unrelated controller viewhands cache.
 for(unsigned selection=0;selection<=DWCustomOperators::Count;++selection) {
  option.current.integer=int(selection);
  uint8_t faction{}; uint32_t west[3]{},east[3]{};
  CHECK(DW_CustomOperators_CardModels(0,&faction,west,east,nullptr,nullptr)==95);
  CHECK(west[0]==31 && east[1]==50);
  CHECK(west[2]==79 && east[2]==80 && faction==1);
  DW_CustomOperators_CardModels(1,&faction,west,east,nullptr,nullptr);
  CHECK(west[0]==31 && east[1]==50);
  alignas(8) uint8_t card[128]{};
  DW_CustomOperators_GetPlayercard(123,"local",card);
  auto *sets=reinterpret_cast<uint32_t *>(card+80);
  CHECK(sets[0]==(selection?59999+selection:100));
  CHECK(sets[1]==(selection?59999+selection:101));
  CHECK(sets[2]==102 && sets[5]==105 && sets[8]==108 && sets[11]==111);
  CHECK(sets[9]==(selection?59999+selection:109));
  DW_CustomOperators_GetPlayercard(456,"remote",card); CHECK(sets[0]==100 && sets[9]==109);
 }
 // Local cosmetic selection never writes the replicated ClientInfo.
 CO_ClientModelSelection wire{}; wire.models[0]=17;wire.models[1]=19;wire.models[2]=23;
 unsigned character=7;playerView.predictedClient=7;bool loaded=false;
 for(unsigned selection=0;selection<=DWCustomOperators::Count;++selection) {
  option.current.integer=int(selection);
  for(unsigned kind=0;kind<3;++kind) {
   const char *expected=kind==0?"stock_head":kind==1?"stock_body":"stock_hands";
   if(selection && kind<2) expected=kind==0?DWCustomOperators::Operators[selection-1].head:DWCustomOperators::Operators[selection-1].body;
   CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,kind,&loaded),expected));
   CHECK(wire.models[0]==17 && wire.models[1]==19 && wire.models[2]==23);
  }
 }
 option.current.integer=2;
 character=8;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));character=7;
 playerView.inKillcam=1;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));playerView.inKillcam=0;
 playerView.movementType=5;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));playerView.movementType=0;
 playerView.otherFlags=0x80000000u;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));playerView.otherFlags=0;
 forceModelFallback=true;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));forceModelFallback=false;
 commonMpState=0;CHECK(Equal(DW_CustomOperators_GetActiveModel(0,&wire,&character,1,&loaded),"stock_body"));commonMpState=2;
 CHECK(DW_CustomOperators_ShouldRecreateLegs(0,7));
 for(unsigned selection=0;selection<=DWCustomOperators::Count;++selection) {
  option.current.integer=int(selection);
  const void *expected=selection ? DWCustomOperators::Operators[selection-1].body : CO_DObjGetModel(nullptr,0);
  CHECK(CO_GetLegsSourceModel(nullptr,0)==expected);
  CHECK(CO_GetLegsSourceModel(nullptr,1)==CO_DObjGetModel(nullptr,1));
 }
 option.current.integer=2;
 missingBody=true;CHECK(CO_GetLegsSourceModel(nullptr,0)==CO_DObjGetModel(nullptr,0));missingBody=false;
 playerView.movementType=5;CHECK(CO_GetLegsSourceModel(nullptr,0)==CO_DObjGetModel(nullptr,0));playerView.movementType=0;
 playerView.inKillcam=1;CHECK(CO_GetLegsSourceModel(nullptr,0)==CO_DObjGetModel(nullptr,0));playerView.inKillcam=0;
 uint16_t cells[24]{}; uint32_t hashes[24]{}; const char *strings[24]{};
 for(unsigned i=0;i<24;++i) {cells[i]=uint16_t(i); strings[i]="metadata"; hashes[i]=CO_TableHash(strings[i]);}
 strings[0]="0"; strings[1]="stock_body"; strings[3]="stock_hands";
 for(unsigned i=0;i<24;++i) hashes[i]=CO_TableHash(strings[i]);
 CO_StringTable table{"mp/cac/bodies.csv",24,1,24,0,cells,hashes,strings};
 CHECK(DW_CustomOperators_TableRows(&table)==1+DWCustomOperators::Count);
 CHECK(Equal(CO_TableLookupNative(DW_CustomOperators_TableView(&table),0,"0",1),"stock_body"));
 CHECK(Equal(CO_TableLookupNative(DW_CustomOperators_TableView(&table),0,"60000",1),DWCustomOperators::Operators[0].body));
 CHECK(Equal(CO_TableLookupNative(DW_CustomOperators_TableView(&table),1,DWCustomOperators::Operators[0].body,0),"60000"));
 CHECK(DW_CustomOperators_TableRow(&table,0,"60001")==2);
 CHECK(Equal(DW_CustomOperators_TableColumn(&table,2,1),DWCustomOperators::Operators[1].body));
 CHECK(Equal(DW_CustomOperators_TableColumn(&table,2,3),"stock_hands"));
 CHECK(Equal(DW_CustomOperators_TableColumn(&table,-1,1),""));
 CHECK(table.rows==1 && strings[1][0]=='s');
 const void *tableOut{}; fakeTable=&table;
 CHECK(DW_CustomOperators_GetTable(table.name,&tableOut)==tableOut && tableOut!=&table);
 CHECK(DW_CustomOperators_TableRows(tableOut)==1+DWCustomOperators::Count);
 int columns[]{0,1};const char *values[]{"60000",DWCustomOperators::Operators[0].body};
 CHECK(DW_CustomOperators_TableMultiRow(&table,columns,values,2)==1);
 s_registeringTables=true;
 CHECK(DW_CustomOperators_TableRows(&table)==1);
 DW_CustomOperators_GetTable(table.name,&tableOut);CHECK(tableOut==&table);
 s_registeringTables=false;
 *reinterpret_cast<uint8_t **>(fakeEntities+0x150)=fakeClient;
 *reinterpret_cast<int *>(fakeClient+0x55FC)=0;
 auto *applied=reinterpret_cast<uint32_t *>(fakeClient+0x56D8);
 option.current.integer=1;
 CHECK(DW_CustomOperators_SetCustomization(nullptr,0)==97);
 CHECK(applied[0]==11 && applied[1]==12 && applied[2]==13);
 fakeBot=true;DW_CustomOperators_SetCustomization(nullptr,0);CHECK(applied[0]==11 && applied[1]==12);fakeBot=false;
 fakeGlobals[0x72]=1;DW_CustomOperators_SetCustomization(nullptr,0);CHECK(applied[0]==11);fakeGlobals[0x72]=0;
 entityXuid=456;DW_CustomOperators_SetCustomization(nullptr,0);CHECK(applied[0]==11 && applied[1]==12);
 remoteCustom=true;DW_CustomOperators_SetCustomization(nullptr,0);CHECK(applied[0]==11 && applied[1]==12);
 remoteCustom=false;entityXuid=123;
 option.current.integer=0;DW_CustomOperators_SetCustomization(nullptr,0);CHECK(applied[0]==11 && applied[1]==12);
 table.name="unrelated.csv";
 CHECK(DW_CustomOperators_TableRows(&table)==1);
 CHECK(Equal(CO_TableLookupNative(DW_CustomOperators_TableView(&table),0,"60000",1),""));
 // Later native registrations must not move our selected package slots.
 CO_RegisterPackage("later_head", "later_head", 0);
 CO_RegisterPackage("later_body", "later_body", 1);
 p[g[0].first + g[0].count - 1].invalid = 1;
 p[g[1].first + g[1].count - 1].invalid = 1;
 option.current.integer = 1;
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 // A preference consumed before package staging must refresh on readiness.
 DW_CustomOperators_ZoneInstalled(false);
 DW_CustomOperators_Frame();
 unsigned beforeReady = refreshed;
 operatorZoneState = 1;
 DW_CustomOperators_ZoneInstalled(true);
 DW_CustomOperators_Frame(); CHECK(refreshed == beforeReady);
 CHECK(bindingsUpdated == 1);
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 operatorZoneState = 2; p[2].invalid = 1;
 DW_CustomOperators_Frame(); CHECK(refreshed == beforeReady);
 CHECK(bindingsUpdated == 2);
 p[2].invalid = 0;
 DW_CustomOperators_Frame(); CHECK(refreshed == beforeReady + 1);
 DW_CustomOperators_ZoneInstalled(true);
 DW_CustomOperators_Frame(); CHECK(refreshed == beforeReady + 1);
 // Unloading either stock dependency blocks selection until both are ready.
 commonMpState = 0;
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 DW_CustomOperators_Frame();
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 commonMpState = 2; globalStreamState = 1; DW_CustomOperators_Frame();
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 globalStreamState = 2; DW_CustomOperators_Frame();
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 p[2].invalid = 1;
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 p[2].invalid = 0;
 DW_CustomOperators_ZoneInstalled(false);
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 DW_CustomOperators_ZoneInstalled(true);
 option.current.integer = 99;
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 option.current.integer = 1; g[0].count = 6143;
 DW_CustomOperators_RegisterHeads("heads");
 DW_CustomOperators_BuildCustomization(CO_LocalCustomization, 31, 7, 49, false);
 CHECK(seenHead == 31 && seenBody == 49);
 return 0;
}
}
"""

def run(args):
    if args.build and not args.snapshot:
        raise ValueError("--build requires --snapshot")
    if args.snapshot:
        args.snapshot = args.snapshot.resolve(strict=True)
        receipt = json.loads((args.snapshot / "generated/custom-operators-integration.json").read_bytes())
        args.manifest = args.manifest or Path(receipt["manifest"])
    args.manifest = args.manifest or ROOT / "data/custom-operators/package/manifest.json"
    args.header_dir = args.header_dir or (args.snapshot / "src" if args.snapshot else
        ROOT / "tools/build/gulag-query-admission-regression/source/src")
    spec = importlib.util.spec_from_file_location("custom_operators", ROOT / "tools/prepare-custom-operators.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows, header = module.operator_data(args.manifest)
    bindings = """#pragma once
#include <stdint.h>
extern "C" {
uint64_t CO_RegisterHeadsNative(const char *);
uint64_t CO_RegisterBodiesNative(const char *);
uint64_t CO_BuildCustomizationNative(void *, unsigned, unsigned, unsigned, bool);
uint16_t CO_RegisterPackage(const char *, const char *, unsigned);
void CO_UpdateLocalCustomization(unsigned);
void CO_Print(int, const char *, ...);
extern uint8_t CO_LocalCustomization[];
uint64_t CO_CardModelsNative(unsigned, uint8_t *, uint32_t *, uint32_t *, void *, void *);
uint64_t CO_GetPlayercardNative(uint64_t, const char *, void *);
void *CO_GetLocalXuid(uint64_t *, unsigned);
void CO_RequestCardUpload(unsigned);
bool CO_UploadCard(unsigned);
void CO_UpdatePackageBindings(const char *);
int CO_TableRowNative(const void *, int, const char *);
const void *CO_GetTableNative(const char *, const void **);
int CO_TableMultiRowNative(const void *, const int *, const char *const *, int);
uint32_t CO_TableHash(const char *);
int CO_Format(char *, uint64_t, const char *, ...);
uint64_t CO_SetCustomizationNative(void *, uint64_t);
extern uint8_t *CO_Entities, *CO_ServerGlobals;
uint64_t CO_SetBody(void *, unsigned);
uint64_t CO_SetHead(void *, unsigned);
uint64_t *CO_PartyXuid(uint64_t *, const void *, int);
void *CO_ServerLobby();
bool CO_IsBot(const void *);
bool CO_CardSelections(uint64_t, const char *, uint8_t *, uint32_t *, uint32_t *);
extern const uint8_t *CO_LocalClientGlobals[];
const char *CO_GetActiveModelNative(unsigned, const void *, const void *, unsigned, bool *);
int CO_GenerateActiveModel(unsigned, const char **, const void *, const void *, unsigned, int);
const void *CO_DObjGetModel(const void *, unsigned);
const void *CO_FindAsset(int, const char *, int);
bool CO_ShouldRecreateLegsNative(unsigned, unsigned);
void CO_UpdateLegsNative(unsigned, const void *);
}
"""
    (ROOT / "data/custom-operators").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "data/custom-operators", prefix="runtime-test-") as tmp:
        directory = Path(tmp)
        (directory / "DW_CustomOperatorsData.h").write_text(header)
        (directory / "DW_CustomOperatorsBindings.h").write_text(bindings)
        (directory / "harness.cpp").write_text(HARNESS)
        obj, dll = directory / "harness.obj", directory / "harness.dll"
        command = [str(LLVM / "clang++.exe"), "--target=x86_64-pc-windows-msvc", "-c",
            str(directory / "harness.cpp"), "-o", str(obj), "-std=c++20", "-O2", "-ffreestanding",
            "-fno-exceptions", "-fno-rtti", "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
            "-I" + str(directory), "-I" + str(ROOT / "integration/replay"),
            "-I" + str(args.header_dir), "-I" + str(ROOT / "data/dw-client/compiler-base/src")]
        subprocess.run(command, check=True)
        # Compile the real owner separately so the mocked callee cannot inline
        # away the Windows x64 stack argument that caused the stock fallback.
        production_obj = directory / "production.obj"
        production_command = list(command)
        production_command[production_command.index(str(directory / "harness.cpp"))] = str(ROOT / "integration/replay/DW_CustomOperators.cpp")
        production_command[production_command.index(str(obj))] = str(production_obj)
        subprocess.run(production_command, check=True)
        import capstone
        from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RSP
        spec_coff = importlib.util.spec_from_file_location("operator_abi_coff", args.header_dir.parent / "tools/coff.py")
        coff_module = importlib.util.module_from_spec(spec_coff)
        spec_coff.loader.exec_module(coff_module)
        compiled = coff_module.read(production_obj)
        owner = next(s for s in compiled["symbols"].values() if s["name"] == "DW_CustomOperators_GetActiveModel" and s["section"] > 0)
        section = compiled["sections"][owner["section"]-1]
        calls = [off for off, idx, _ in section["relocations"] if compiled["symbols"][idx]["name"] == "CO_GenerateActiveModel"]
        assert len(calls) == 1
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(section["data"][owner["value"]:calls[0]+4], owner["value"]))
        stores = [i for i in instructions if i.mnemonic == "mov" and len(i.operands) == 2 and
            i.operands[0].type == X86_OP_MEM and i.operands[0].mem.base == X86_REG_RSP and
            i.operands[0].mem.disp == 0x28]
        assert stores and stores[-1].operands[0].size == 4 and stores[-1].operands[1].type == X86_OP_IMM and stores[-1].operands[1].imm == 0, "Native force-default argument must clear all four bytes"
        subprocess.run([str(LLVM / "lld-link.exe"), "/dll", "/noentry", "/nodefaultlib",
                        "/out:" + str(dll), str(obj)], check=True)
        lib = ctypes.CDLL(str(dll))
        try:
            result = lib.Test_Run()
            assert result == 0, "Custom operator contract failed at harness line " + str(result)
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(lib._handle)
    result = dict(passed=True, game_launched=False, modeled_engine_boundaries=True,
        force_default_stack_argument_bytes=4,
        operators=rows, source_sha256=hashlib.sha256((ROOT / "integration/replay/DW_CustomOperators.cpp").read_bytes()).hexdigest(),
        checks=["stock and remote profile routing preserved", "local visual selection with unchanged network appearance",
                "package primary/secondary/category/hands layout", "random pools unchanged",
                "uploaded playercards remain stock; local frontend preview retains custom selection",
                "complete native tables retain stock rows and support lookup, reverse/multiple row, column and count",
                "server body, head and collision selection remain native for every player",
                "capacity, staging and native binding failures retain stock selection", "stable selected slots after later registrations", "refresh only after custom and stock dependency native completion; unload/reload restores stock/custom"])
    if args.snapshot:
        result["snapshot"] = verify_snapshot(args.snapshot, module)
    if args.build:
        result["linked"] = verify_linked(args.snapshot, args.build, module)
        for field in ("package_proof_sha256", "compiled_package_header_sha256", "executable_sha256"):
            result[field] = result["linked"][field]
    result["native_profile_fields"] = verify_native_profile_fields(module)
    result["native_tables"] = native_table_cases(module)
    result["native_alwaysloaded"] = native_model_cases(module)
    result["native_legs_cache"] = native_legs_cache_cases(module)
    manifest_path = (args.snapshot / "generated/custom-operators-package/manifest.json"
                     if args.build else args.manifest)
    result["native_package_models"] = verify_native_model_flags(manifest_path)
    return result


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_snapshot(snapshot, preparer):
    proof = json.loads((snapshot / "generated/custom-operators-integration.json").read_bytes())
    assert proof["passed"] and proof["image_sha256"] == preparer.TARGET
    assert proof["source_sha256"] == sha(snapshot / proof["source"])
    assert sha(snapshot / proof["source"]) == sha(ROOT / "integration/replay/DW_CustomOperators.cpp"), "Stale runtime owner"
    assert proof["generator_sha256"] == sha(ROOT / "tools/prepare-custom-operators.py"), "Stale preparer"
    for name, digest in proof["dependencies"].items():
        assert sha(snapshot / "src" / name) == digest, ("Changed prepared dependency", name)
    assert sha(proof["manifest"]) == proof["manifest_sha256"], "Changed operator manifest"
    rows, data = preparer.operator_data(Path(proof["manifest"]))
    assert (snapshot / "src/DW_CustomOperatorsData.h").read_text() == data
    units = json.loads((snapshot / "source-units.json").read_bytes())
    for identity, symbol, helper, size, digest in preparer.OWNERS:
        owners = [r for r in units["units"] if r["function_id"] == identity]
        assert owners == [dict(source=preparer.SOURCE, symbol=symbol, function_id=identity)]
        if not helper:
            assert not proof["owners"][symbol]["unwind"]
            continue
        clones = [r for r in proof["clones"] if r["helper"] == helper]
        assert len(clones) == 1 and clones[0]["preserved_outside_fixups"]
        assert clones[0]["bytes"] == size and clones[0]["identity"] == identity
        assert proof["owners"][symbol]["sha256"] == digest
        source = snapshot / "generated/custom-operators" / (helper + ".cpp")
        obj = source.with_suffix(".obj")
        assert sha(source) == clones[0]["source_sha256"] and sha(obj) == clones[0]["object_sha256"]
    return dict(passed=True, source_sha256=proof["source_sha256"], manifest_sha256=proof["manifest_sha256"],
                prepared_dependencies=len(proof["dependencies"]), operators=rows)


def verify_native_model_flags(manifest_path):
    """Read each model's actual serialized flags at native-reader-proven root offsets."""
    import struct
    manifest = json.loads(Path(manifest_path).read_bytes())
    reader = manifest["native_reader"]
    trace = Path(reader["manifest_path"]).parent / "stream-trace.jsonl"
    assert sha(trace) == reader["trace_summary"]["stream_trace_sha256"]
    fastfile = Path(manifest_path).parent / "custom_operators.ff"
    assert sha(fastfile) == manifest["fastfile_sha256"] == reader["candidate_artifacts"][".ff"]["sha256"]
    contents = fastfile.read_bytes()
    assert contents[:8] == b"IWffc100"
    # This package's native writer emits the uncompressed Replay envelope;
    # the native reader independently accounts for every byte in its payload.
    payload_size = reader["manifest"]["serialized_bytes_read"]
    assert len(contents) == payload_size + 140
    payload = contents[140:]
    roots = [json.loads(line) for line in trace.read_text().splitlines()]
    assert not any(e.get('type_id') == 61 for e in roots), 'Local cosmetics must not change shared network string tables'
    models = {m['name']:m for source in manifest['model_inputs']
              for m in json.loads(Path(source['path']).read_bytes())['models']}
    rows = []
    for event in roots:
        if event.get("type_id") == 9 and event.get("kind") == "load_stream_call" and event.get("size") == 688 and event.get("at_start"):
            offset = event["serialized_input_cursor"]
            name = payload[offset + 688:offset + 944].split(b"\0", 1)[0].decode("ascii")
            flags = struct.unpack_from("<I", payload, offset + 28)[0]
            regular, root_count, client = struct.unpack_from('<BBH',payload,offset+20)
            model = models[name]
            assert (regular,root_count,client) == (model['numBones'],model['numRootBones'],model['numClientBones'])
            assert len(model['boneNames']) == regular+client
            assert len(model['skeleton']['partClassification']) == regular
            assert flags & 0x18000 == 0, ("Model rejected by native alwaysloaded validator", name, flags)
            assert flags & 0x40000, ("Weighted operator missing the native skinned-surface flag", name, flags)
            rows.append(dict(name=name, flags=flags, regular_bones=regular,client_bones=client,
                             root_archive_offset=offset, root_bytes=688))
    expected = {operator[kind] for operator in manifest["operators"] for kind in ("head", "body")}
    assert len(rows) == 4 and {row["name"] for row in rows} == expected
    skinning = verify_gpu_skin_weights(manifest, payload, roots)
    return dict(passed=True, fastfile_sha256=manifest["fastfile_sha256"], trace_sha256=sha(trace),
                models=rows, gpu_skin_weights=skinning)


def verify_gpu_skin_weights(manifest, payload, events):
    """Check every serialized influence using Replay's GPU shader addressing."""
    import struct
    inputs = {}
    for source in manifest["model_inputs"]:
        assert sha(source["path"]) == source["sha256"], "Changed operator model input"
        for model in json.loads(Path(source["path"]).read_bytes())["models"]:
            inputs[model["name"] + "_surfs"] = model
    rows = []
    # Original Load_XModelSurfs, Load_XSurfaceArray and Load_XSurface callers,
    # as recorded by the independently executed native reader.
    for root in events:
        if not (root.get("type_id") == 8 and root.get("kind") == "load_stream_call"
                and root.get("at_start") and root.get("size") == 96
                and root.get("caller_rva") == 0xe2a806):
            continue
        cursor = root["serialized_input_cursor"]
        name = payload[cursor+96:cursor+352].split(b"\0", 1)[0].decode("ascii")
        model = inputs[name]
        loads = [e for e in events if e.get("type_id") == 8
                 and e.get("xasset_index") == root["xasset_index"]
                 and e.get("kind") == "load_stream_call" and e.get("at_start")]
        arrays = [e for e in loads if e.get("caller_rva") == 0xe2a888]
        blends = [e for e in loads if e.get("caller_rva") == 0xe2adb0]
        assert len(arrays) == 1
        assert arrays[0]["size"] == 192 * len(model["surfaces"])
        assert len(blends) == len(model["surfaces"])
        vertices = influences = 0
        for i, (surface, blend) in enumerate(zip(model["surfaces"], blends)):
            header = arrays[0]["serialized_input_cursor"] + i * 192
            count = struct.unpack_from("<H", payload, header+2)[0]
            tiers = struct.unpack_from("<8H", payload, header+16)
            size = struct.unpack_from("<I", payload, header+32)[0]
            assert list(struct.unpack_from('<8I',payload,header+112)) == surface['partBits']
            assert list(tiers[:4]) == surface["blendCounts"] and not any(tiers[4:])
            assert count == sum(tiers) == len(surface["vertices"])
            assert size == blend["size"] == sum(n*(tier+1)*4 for tier,n in enumerate(tiers))
            packed = struct.unpack_from("<"+"I"*(size//4), payload, blend["serialized_input_cursor"])
            source = surface["blendWords"]
            source_cursor = packed_cursor = 0
            for tier, n in enumerate(tiers):
                for vertex in range(n):
                    weight_sum = 0
                    for influence in range(tier+1):
                        # cs_skinning_unified_main: weightOffset + vertexIndex
                        # + blendVertCount * influence, in DWORDs.
                        actual = packed[packed_cursor + n*influence + vertex]
                        bone, weight = actual & 65535, actual >> 16
                        offset = source[source_cursor]
                        source_cursor += 1
                        expected_weight = source[source_cursor] if influence else 0
                        source_cursor += bool(influence)
                        assert offset % 64 == 0
                        assert bone < len(model["boneNames"]) and (bone,weight) == (offset//64,expected_weight), (
                            "GPU skin influence mismatch", name, i, tier+1, vertex, influence, bone, weight)
                        weight_sum += weight
                        influences += 1
                    assert weight_sum <= 65535
                packed_cursor += n*(tier+1)
            assert source_cursor == len(source) and packed_cursor == len(packed)
            vertices += count
        rows.append(dict(name=name, surfaces=len(blends), vertices=vertices, influences=influences))
    assert len(rows) == len(inputs) == 4 and {r["name"] for r in rows} == set(inputs)
    return dict(passed=True, addressing="influence blocks within each blend-count tier",
                gpu_executed=False, shader="cs_skinning_unified.hlsl/cs_skinning_unified_main",
                models=rows)


def verify_native_profile_fields(preparer):
    """Bind the retained native field round trips to the actual exported DDL."""
    from itertools import product
    receipt_path = ROOT / "data/custom-operators/profile-ddl-review/native-short-proof.json"
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt["image_sha256"] == preparer.TARGET == sha(preparer.IMAGE)
    asset = Path(receipt["asset"])
    assert sha(asset) == receipt["asset_sha256"] == "69b7983d0d50c030c308587074f5fbf51abbbc12902f34818b538ab1fcd65c59"
    definition = json.loads(asset.read_bytes())["asset"]["fields"]["ddlDef"]["values"][0]
    assert definition["version"] == receipt["ddl_version"] == 109
    assert definition["byteSize"] == receipt["ddl_byte_size"] == 232
    structures = definition["structList"]["values"]
    sets = next(m for m in structures[0]["members"]["values"] if m["name"]["string"] == "customizationSets")
    entry = structures[sets["externalIndex"]]
    members = {m["name"]["string"]: m for m in entry["members"]["values"] if
               m["name"]["string"] in ("customization_mp_public", "customization_mp_private")}
    assert len(members) == 2 and sets["arraySize"] == 2
    for member in members.values():
        assert (member["bitSize"], member["arraySize"], member["limitSize"], member["rangeLimit"], member["type"]) == (48,3,16,65535,1)
    actual = set()
    for row in receipt["cases"]:
        key = row["set_index"], row["member"], row["model_index"], row["input"]
        assert key not in actual; actual.add(key)
        member = members[row["member"]]
        assert row["root_relative_bit_offset"] == sets["offset"] + entry["bitSize"]*row["set_index"] + member["offset"] + 16*row["model_index"]
        assert row["native_set_return"] == 1
        assert row["native_get_return_rax"] == row["native_get_return_u16"] == row["input"]
        assert row["little_endian_bytes"] == row["input"].to_bytes(2,"little").hex()
    assert actual == set(product(range(2), members, range(3), (0,32767,32768,60000,60001,65535)))
    return dict(passed=True, receipt_sha256=sha(receipt_path), ddl_asset_sha256=sha(asset),
                ddl_version=109, native_field_roundtrip_cases=len(actual), custom_primary_ids=[60000,60001],
                retained_native_execution_receipt=True, executed_during_this_test=False,
                full_playercard_codec_executed=False,
                extent="Original DDL_SetShort/GetShort field round trips and actual DDL widths; complete unchanged playercard codec was not executed")


def native_table_cases(preparer):
    """Run Replay's unchanged table consumers on the complete extended layout."""
    import struct
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_UNMAPPED
    from unicorn import x86_const as x
    assert sha(preparer.IMAGE) == preparer.TARGET
    pe = pefile.PE(str(preparer.IMAGE), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = set()
    def page(address):
        address &= -4096
        if address in pages: return
        vm.mem_map(address, 4096); pages.add(address)
        if base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            data = pe.get_data(address - base, 4096)
            if data: vm.mem_write(address, data[:4096])
    def put(address, data):
        for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096): page(at)
        vm.mem_write(address, data)
    def missing(uc, access, address, size, value, context):
        page(address); return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    scratch, stack, stop = 0x30000000, 0x31008000, 0x32000000
    put(scratch, bytes(0x10000)); put(stack-4096, bytes(8192)); put(stop,b"\xc3")
    def call(rva, *args):
        for reg, value in zip((x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9),args): vm.reg_write(reg,value)
        vm.reg_write(x.UC_X86_REG_RSP,stack-8);put(stack-8,struct.pack("<Q",stop))
        vm.emu_start(base+rva,stop,count=100000)
        assert vm.reg_read(x.UC_X86_REG_RIP)==stop
        return vm.reg_read(x.UC_X86_REG_RAX)
    def string(address):
        page(address)
        return bytes(vm.mem_read(address,128)).split(b"\0",1)[0].decode()
    rows = [["0","stock_body","stock_metadata"],["60000","dw_operator_nicky_body","stock_metadata"],
            ["60001","dw_operator_bo2_body","stock_metadata"]]
    texts = [value for row in rows for value in row]
    cells, hashes, strings = scratch+0x100,scratch+0x200,scratch+0x300
    pointers=[]
    for i,text in enumerate(texts):
        pointer=scratch+0x1000+i*128;put(pointer,text.encode()+b"\0");pointers.append(pointer)
    put(cells,struct.pack("<"+"H"*len(texts),*range(len(texts))))
    put(strings,struct.pack("<"+"Q"*len(texts),*pointers))
    put(hashes,struct.pack("<"+"I"*len(texts),*(call(0x13E3410,p)&0xffffffff for p in pointers)))
    put(scratch,struct.pack("<QiiiiQQQ",0,3,3,len(texts),0,cells,hashes,strings))
    assertions=0
    for row in range(3):
        for column in range(3):
            assert string(call(0x13E2B40,scratch,row,column))==rows[row][column];assertions+=1
        assert call(0x13E2FE0,scratch,0,pointers[row*3])==row;assertions+=1
        assert string(call(0x13E2BA0,scratch,0,pointers[row*3],1))==rows[row][1];assertions+=1
    assert call(0x13E2B90,scratch)==3;assertions+=1
    for row,column in [(3,0),(0,3),(0,0xffffffff),(0xffffffff,0)]:
        assert string(call(0x13E2B40,scratch,row,column))=="";assertions+=1
    return dict(passed=True, original_pe_executed=True, game_launched=False, modeled_table_input=True,
                source_image_sha256=preparer.TARGET, assertions=assertions,
                native_hash_lookup_row_column_and_count=True)


def native_model_cases(preparer):
    """Execute the original native validator and availability paths with modeled DB inputs."""
    import struct
    import pefile
    import capstone
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9
    from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP
    assert sha(preparer.IMAGE) == preparer.TARGET
    pe = pefile.PE(str(preparer.IMAGE), fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    # These Replay identities were inspected in the target SQLite pseudocode
    # and independently decoded here from the hash-bound original PE.
    addresses = dict(validate=0x10E4460, model_name=0x10E34D0, loaded=0x15F6290,
                     registered=0x15F6E70, lookup=0x15F66A0,
                     print_error=0x12B0570, print=0x12B0820)
    catalog = json.loads((ROOT / "data/dw-client/compiler-base/generated/function-catalog.json").read_bytes())
    functions = {r["rva"]: r for r in catalog["functions"] if not r.get("quarantined")}
    # Resolve DB_FindXAssetHeader from the catalog rather than a borrowed RVA.
    db = [r for r in functions.values() if "DB_FindXAssetHeader" in (r["name"], *r["aliases"])]
    assert len(db) == 1
    addresses["find_asset"] = db[0]["rva"]
    native = {}
    expected_native = {
        "validate": (395, "0f99cd4098012d06b41a09bcd797fe3bf626d21ef21bc05eb2c9edf1f1cba3a7"),
        "model_name": (141, "11faa5cc6f4f110ca5fdb31a564cc6b762ea51793b1674ac14e2e8babce45475"),
        "loaded": (248, "f13889c6fab68f56a553142246cdb570ad2a2a2897e37edd84eb0682f68582ea"),
    }
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    for role in ("validate", "model_name", "loaded"):
        rva = addresses[role]
        ranges = preparer.unwind_family(pe, rva)
        body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in ranges)
        native[role] = dict(identity=functions[rva]["id"], sha256=hashlib.sha256(body).hexdigest(), bytes=len(body))
        assert (len(body), native[role]["sha256"]) == expected_native[role]
        if role == "validate":
            instructions = list(decoder.disasm(body, base + rva))
    def rip_lea(register):
        values = [i.address + i.size + i.operands[1].mem.disp for i in instructions if
            i.mnemonic == "lea" and i.reg_name(i.operands[0].reg) == register and
            i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP]
        assert len(values) == 1
        return values[0]
    packages, groups = rip_lea("r12"), rip_lea("rbp") - 4
    enabled = [i.address + i.size + i.operands[0].mem.disp for i in instructions if
        i.mnemonic == "cmp" and i.operands[0].type == X86_OP_MEM and
        i.operands[0].mem.base == X86_REG_RIP]
    assert len(enabled) == 1
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    def page(address):
        address &= -4096
        if address not in mapped:
            vm.mem_map(address, 4096)
            mapped.add(address)
            if base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                data = pe.get_data(address - base, 4096)
                if data:
                    vm.mem_write(address, data[:4096])
    def put(address, data):
        for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096):
            page(at)
        vm.mem_write(address, data)
    def unmapped(uc, access, address, size, value, data):
        page(address)
        return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)
    scratch, stack, stop = 0x30000000, 0x31008000, 0x32000000
    put(scratch, bytes(4096)); put(stack - 4096, bytes(8192)); put(stop, b"\xc3")
    names = (scratch + 256, scratch + 512)
    for pointer, value in zip(names, (b"dw_operator_nicky_head\0", b"dw_operator_nicky_body\0")):
        put(pointer, value)
    model = scratch + 1024
    registered, db_present, requests = False, True, []
    def hook(uc, address, size, data):
        role = next((role for role in ("registered", "lookup", "find_asset", "print_error", "print")
                     if address == base + addresses[role]), None)
        if role is None:
            return
        requests.append(role)
        result = int(registered) if role == "registered" else 0xFFFF if role == "lookup" else model if role == "find_asset" and db_present else 0
        if role == "find_asset":
            assert uc.reg_read(UC_X86_REG_RCX) == 9
        sp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        uc.reg_write(UC_X86_REG_RAX, result)
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)
    vm.hook_add(UC_HOOK_CODE, hook)
    def call(role, *args):
        for register, value in zip((UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), args):
            vm.reg_write(register, value)
        put(stack, struct.pack("<Q", stop))
        vm.reg_write(UC_X86_REG_RSP, stack)
        vm.emu_start(base + addresses[role], stop, count=100000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        return vm.reg_read(UC_X86_REG_RAX)
    put(enabled[0], struct.pack("<I", 1))
    for kind, first in enumerate((0, 6143, 7167)):
        put(groups + kind * 16, struct.pack("<HHIII", first, 0, int(kind < 2), 1, 0))
    for index, name in zip((0, 6143), names):
        put(packages + index * 40, struct.pack("<QQIHHHHIHBBI", name, name, 0,
            0xFFFF, 60000, 0 if index == 0 else 0xFFFF, 0, 0, 7167, 0, 0, 0))
    results = {}
    for label, flags, present, transient in (("permanent_common", 0, True, False),
            ("skinned_permanent_common", 0x40000, True, False),
            ("loose_streamed_rejected", 0x8000, True, False),
            ("missing_model_rejected", 0, False, False), ("transient_fallback_rejected", 0, True, True)):
        db_present, registered = present, transient
        put(model, bytes(28) + struct.pack("<I", flags))
        requests.clear()
        call("validate", names[0])
        invalid = [vm.mem_read(packages + index * 40 + 35, 1)[0] for index in (0, 6143)]
        expected = int(label not in ("permanent_common", "skinned_permanent_common"))
        assert invalid == [expected, expected], (label, invalid)
        results[label] = dict(invalid=invalid, db_lookups=requests.count("find_asset"), transient_queries=requests.count("registered"))
    registered = False
    assert call("model_name", 0, 0, 0) == names[0]
    assert call("model_name", 1, 0, 0) == names[1]
    requests.clear()
    assert call("loaded", names[1], 9) & 0xFF == 1
    assert requests == ["lookup"], requests
    return dict(passed=True, modeled_asset_database=True, game_launched=False, native=native, cases=results,
        ordinal_name_lookup=True, absent_transient_registration_is_loaded=True)


def native_legs_cache_cases(preparer):
    """Run the original legs cache checks with distinct source and cached bodies."""
    import struct
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP
    pe = pefile.PE(str(preparer.IMAGE), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    body = pe.get_data(0x16DF380, 434)
    assert hashlib.sha256(body).hexdigest() == "662db0d1fdb1a9a3a73c7ff76d73caa47cfc53b0cd7c1f0896783c495d56aafc"
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    arena = 0x30000000
    vm.mem_map(arena, 0x100000)
    pages = set()
    def page(at):
        at &= -4096
        if arena <= at < arena + 0x100000 or at in pages:
            return
        assert base <= at < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(at,4096)
        data = pe.get_data(at-base,4096)
        if data: vm.mem_write(at,data)
        pages.add(at)
    def put(at,data):
        for p in range(at & -4096,(at+len(data)+4095) & -4096,4096): page(p)
        vm.mem_write(at,data)
    def missing(machine,access,address,size,value,data):
        page(address);page(address+size-1);return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED,missing)
    cg,objects,option,stack,stop = arena+0x10000,arena+0x1000,arena+0x5000,arena+0xF0008,arena+0xF1000
    source_object,cached_object = objects+336,objects+672
    put(base+0xF26F940,struct.pack('<Q',cg))
    put(base+0xD45EC50,struct.pack('<Q',objects))
    put(base+0xD45EC60,struct.pack('<H',1))
    put(base+0xD45FCE4,struct.pack('<H',2))
    put(base+0xEEB08A0,struct.pack('<Q',option))
    models=[]
    for i,name in enumerate((b'stock_body\0',b'dw_operator_nicky_body\0',b'dw_operator_bo2_body\0')):
        model,text=arena+0x2000+i*688,arena+0x4000+i*64
        put(model,struct.pack('<Q',text));put(text,name);models.append(model)
    current,cached = models[0],models[0]
    def hook(machine,address,size,data):
        rva=address-base
        if rva not in (0x10C8980,0x149BAF0,0xCB6340):return
        if rva==0x149BAF0:
            obj=machine.reg_read(UC_X86_REG_RCX)
            assert obj in (source_object,cached_object)
            value=current if obj==source_object else cached
        else:value=0
        sp=machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RAX,value)
        machine.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',machine.mem_read(sp,8))[0])
        machine.reg_write(UC_X86_REG_RSP,sp+8)
    vm.hook_add(UC_HOOK_CODE,hook)
    results=[]
    for compare_names in (False,True):
        put(option+40,bytes([compare_names]))
        for selected,previous in ((0,0),(1,0),(1,1),(2,1),(2,2),(0,2)):
            current,cached=models[selected],models[previous]
            put(cg+103276,(b'stock_body',b'dw_operator_nicky_body',b'dw_operator_bo2_body')[previous]+b'\0')
            put(stack,struct.pack('<Q',stop))
            vm.reg_write(UC_X86_REG_RCX,0);vm.reg_write(UC_X86_REG_RDX,0);vm.reg_write(UC_X86_REG_RSP,stack)
            vm.emu_start(base+0x16DF380,stop,count=1000)
            assert vm.reg_read(UC_X86_REG_RIP)==stop
            recreate=bool(vm.reg_read(UC_X86_REG_RAX)&255)
            assert recreate==(selected!=previous),(compare_names,selected,previous,recreate)
            results.append(dict(compare_names=compare_names,selected=selected,cached=previous,recreate=recreate))
    return dict(passed=True,original_engine_instructions=True,cases=results,game_launched=False)


def verify_linked(snapshot, build, preparer):
    """Verify actual linked sections, relocations, native aliases and unwind records."""
    import sys
    import struct
    import pefile
    sys.path.insert(0, str(snapshot / "tools"))
    from coff import read
    spec = importlib.util.spec_from_file_location("custom_linked_gate", ROOT / "tools/test-weapon-inspect.py")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    build = build.resolve(strict=True)
    report = json.loads((build / "build-report.json").read_bytes())
    proof = json.loads((snapshot / "generated/custom-operators-integration.json").read_bytes())
    assert Path(report["source_root"]).resolve() == snapshot, "Different linked source snapshot"
    assert report["input_sha256"] == preparer.TARGET and report["unresolved_symbols"] == 0
    executable = Path(report["executable"]).resolve(strict=True)
    assert executable.is_relative_to(build) and sha(executable) == report["sha256"]
    pe = pefile.PE(str(executable))
    symbols = report["symbols"]
    roots = [row[1] for row in preparer.OWNERS] + ["DW_CustomOperators_Frame",
        "DW_CustomOperators_ZoneInstalled", "DW_CustomOperators_RegisterDvars", "DW_CustomOperators_TableView"]
    objects, source_units = {}, {}
    expected_sources = ("DW_CustomOperators.cpp", "DW_CustomOperators_Native.cpp", "DW_BotStyleZone.cpp", "DW_MapAvailability.cpp")
    for name in expected_sources:
        rows = [r for r in report["cpp"] if Path(r["source"]).as_posix() == "src/" + name]
        assert len(rows) == 1, ("Missing/duplicate compiled unit", name)
        row = rows[0]
        assert row["source_sha256"] == sha(snapshot / "src" / name)
        obj = Path(row["object"]).resolve(strict=True)
        assert obj.is_relative_to(build) and sha(obj) == row["object_sha256"]
        dependencies = {Path(d["path"]).resolve(): d["sha256"] for d in row["dependencies"]}
        assert len(dependencies) == len(row["dependencies"])
        for path, digest in dependencies.items():
            assert sha(path) == digest, ("Changed compiled dependency", str(path))
        required = [name]
        if name == "DW_CustomOperators.cpp":
            required += ["DW_CustomOperators.h", "DW_CustomOperatorsBindings.h", "DW_CustomOperatorsData.h", "DW_BotBindings.h"]
        if name == "DW_BotStyleZone.cpp":
            required += ["DW_CustomOperatorsPackage.h", "DW_CustomOperators.h"]
            assert sha(snapshot / "src" / name) == sha(ROOT / "integration/replay" / name)
        for dependency in required:
            path = (snapshot / "src" / dependency).resolve()
            assert dependencies[path] == sha(path), ("Missing linked dependency", dependency)
        objects[name] = read(obj)
        source_units[name] = dict(object_sha256=row["object_sha256"], dependencies=len(dependencies))
    package_path = snapshot / "generated/custom-operators-package/package-proof.json"
    package = json.loads(package_path.read_bytes())
    assert package["production_ready"], "Custom operator package not production ready"
    header = snapshot / "src/DW_CustomOperatorsPackage.h"
    assert sha(header) == package["header_sha256"], "Changed embedded custom model package"
    package_manifest = package_path.parent / "manifest.json"
    assert sha(package_manifest) == package["manifest_sha256"]
    assert json.loads(package_manifest.read_bytes())["operators"] == proof["operators"]
    installed = []
    for entry in package["installation_manifest"]:
        source = Path(entry["source"]).resolve(strict=True)
        assert source.is_relative_to(package_path.parent.resolve()), "Package source escaped frozen snapshot"
        assert source.stat().st_size == entry["size"] and sha(source) == entry["sha256"]
        relative = Path(entry["relative_path"])
        assert not relative.is_absolute() and ".." not in relative.parts
        installed.append(entry["relative_path"])
    assert installed and len(set(installed)) == len(installed)
    # Verify the actual linked zone code and its reachable package descriptor,
    # embedded fastfile/patch arrays and installation names against its COFF.
    zone_graph = checker.linked_object(pe, objects["DW_BotStyleZone.cpp"], symbols,
        ["DW_BotStyleZone_LoadFastfiles"], report["rva_map"]["ranges"])
    linked = checker.linked_object(pe, objects["DW_CustomOperators.cpp"], symbols, roots,
                                  report["rva_map"]["ranges"])
    for alias, identity in proof["imports"].items():
        assert alias in symbols and identity in symbols and symbols[alias] == symbols[identity], alias
    assert symbols["fn_cdf2d126fdf66569"] == symbols["func_1413E2BA0"], "Native lookup must retain its map-availability owner"
    table_composition = checker.linked_object(pe, objects["DW_MapAvailability.cpp"], symbols,
        ["func_1413E2BA0"], report["rva_map"]["ranges"])
    native, unwind = {}, {}
    for identity, symbol, helper, size, digest in preparer.OWNERS:
        assert symbols[identity] == symbols[symbol]
        mappings = [r for r in report["source_units"] if r["function_id"] == identity]
        assert mappings == [dict(source=preparer.SOURCE, symbol=symbol, function_id=identity)]
        if not helper:
            continue
        assert symbols[helper] != symbols[symbol]
        reference = read(snapshot / "generated/custom-operators" / (helper + ".obj"))
        native[helper] = checker.linked_object(pe, reference, symbols, [helper], report["rva_map"]["ranges"])
        start = symbols[helper]
        originals = proof["owners"][symbol]["unwind"]
        original_start = originals[0]["begin"]
        runtime = sorted((e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION
            if e.struct.BeginAddress < start + size and e.struct.EndAddress > start), key=lambda e: e.BeginAddress)
        assert len(runtime) == len(originals), ("Changed unwind record count", helper)
        assert [(r.BeginAddress - start, r.EndAddress - start) for r in runtime] == [
            (r["begin"] - original_start, r["end"] - original_start) for r in originals]
        unwind_map = {r["unwind_rva"]: current.UnwindData for r, current in zip(originals, runtime)}
        for original, current in zip(originals, runtime):
            expected = bytes.fromhex(original["bytes"])
            actual = pe.get_data(current.UnwindData, len(expected))
            prefix = 4 + ((expected[2] + 1) & ~1) * 2
            assert actual[:prefix] == expected[:prefix], ("Changed unwind instructions", helper)
            flags = expected[0] >> 3
            assert flags in (0, 3, 4), ("Unsupported owner unwind flags", helper, flags)
            if flags == 3:
                clone = next(r for r in proof["clones"] if r["helper"] == helper)
                handler = [r for r in clone["external_fixups"] if r.get("section") == ".xdata" and
                           r["original_site_rva"] == original["unwind_rva"] + prefix]
                assert len(handler) == 1
                assert struct.unpack_from("<I", actual, prefix)[0] == symbols[handler[0]["stable_id"]]
                assert actual[prefix + 4:] == expected[prefix + 4:], "Changed GS handler data"
            if flags == 4:
                begin, end, target = struct.unpack_from("<III", expected, prefix)
                assert struct.unpack_from("<III", actual, prefix) == (
                    start + begin - original_start, start + end - original_start, unwind_map[target]), "Wrong unwind chain"
        unwind[helper] = len(runtime)
    return dict(passed=True, executable=str(executable), executable_sha256=report["sha256"],
        package_proof_sha256=sha(package_path), compiled_package_header_sha256=sha(header),
        frozen_package_files=len(installed), zone_sections=zone_graph,
        callback_sections=linked, native_sections=native, native_unwind_records=unwind, sources=source_units,
        native_table_composition=table_composition,
        game_launched=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--header-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as error:
        result = dict(passed=False, game_launched=False, error_type=type(error).__name__, error=str(error))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        raise
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
