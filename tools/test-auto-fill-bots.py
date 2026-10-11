"""Compile extracted production auto-fill policy and both changed translation units; no server/game."""

import argparse, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def extract(source, signature):
    begin = source.index(signature)
    opening = source.index("{", begin)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[begin:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = (ROOT / "src/matchmaking_services.cpp").read_text()
    signatures = [
        "        bool lobbyWaitingForStart(",
        "        bool operatorCanStart(",
        "        uint64_t autoFillTarget(",
        "        void refreshAutoFill(",
        "        uint64_t occupiedSlots(const Json &members, const Json &slots)\n        {",
        "        bool slotsAvailable(",
        "        Json nativeBackendDocument(",
    ]
    bodies = [extract(source, s) for s in signatures]
    start = source.index("                const auto submittedPhase = host.value(")
    stop = source.index('                if (host.contains("dw_bot_count"))', start)
    update = source[start:stop]
    harness = r"""
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
using Json=nlohmann::json;
namespace wire { void require(bool v) { if(!v) throw std::runtime_error("rejected"); } }
uint64_t clockMs=100000; uint64_t autoFillNowMilliseconds(){return clockMs;} uint64_t now(){return 1;}
uint64_t occupiedSlots(const Json &, const Json &);
Json requestedSlots(const Json &q){return q.value("slots",Json::object());}
Json lobbySlots(const Json &l){return l.at("backend_doc").value("player_id_to_slots",Json::object());}
bool member(const Json &l,uint64_t u){return std::find(l.at("members").begin(),l.at("members").end(),Json(u))!=l.at("members").end();}
@@BODIES@@
std::vector<int> reconcileMembers(int,int,Json&,Json&){return {};}
void apply(Json &lobby,Json host){const int root=0,id=0;const bool migration=false;@@UPDATE@@}
void check(bool b,int line){if(!b){std::printf("FAIL line%d\n",line);std::exit(1);}}
#define CHECK(x) check((x),__LINE__)
Json base(){return Json{{"update_id",uint64_t{1}},{"members",Json::array({uint64_t{1}})},{"maximum_members",uint64_t{12}},{"host_ready",true},{"expires",uint64_t{999999}},
 {"host_doc",{{"game_state",{{"state","intermission"}}}}},{"backend_doc",{{"player_id_to_slots",Json::object()}}}};}
uint64_t requestToken=0;
Json request(uint64_t count,bool complete=false,bool enabled=true){return Json{{"dw_auto_fill_request",++requestToken},{"game_state",{{"state","intermission"}}},{"dw_auto_fill_bots",enabled},{"dw_auto_fill_complete",complete},{"dw_bot_count",count}};}
bool reject(Json &l,Json h){auto copy=l;try{apply(copy,h);return false;}catch(const std::exception&){return true;}}
int exercise(){
 auto l=base();apply(l,request(0));CHECK(l["auto_fill_target"]==11 && !operatorCanStart(l));auto armed=l["auto_fill_started_ms"];auto duplicate=request(0);duplicate["dw_auto_fill_request"]=l["auto_fill_request"];CHECK(reject(l,duplicate));
 auto pending=request(0);pending["game_state"]["state"]="countdown";CHECK(reject(l,pending));
 auto published=nativeBackendDocument(l)["ruleset_payload"]["dvar_overrides"];CHECK(published["replay_dw_autoFillBotsActive"]==1 && published["replay_dw_autoFillBotsComplete"]==0 && published["replay_dw_autoFillBotTarget"]==11 && published["replay_dw_autoFillRevision"]==1);
 clockMs=129999;apply(l,request(11));CHECK(l["operator_bot_count"]==0 && l["auto_fill_started_ms"]==armed);
 clockMs=137500;apply(l,request(11));CHECK(l["operator_bot_count"]==5);CHECK(reject(l,request(11,true)));
 clockMs=145000;CHECK(reject(l,request(11,true)));apply(l,request(11));CHECK(l["operator_bot_count"]==11);
 apply(l,request(11,true));CHECK(operatorCanStart(l));
 // Actual admission function must admit humans even when auto bots occupy all remaining slots.
 Json q{{"members",Json::array({uint64_t{2}})}};CHECK(slotsAvailable(l,q));
 l["members"].push_back(uint64_t{2});refreshAutoFill(l);CHECK(l["auto_fill_target"]==10 && l["operator_bot_count"]==10 && !operatorCanStart(l));
 apply(l,request(10,true));CHECK(operatorCanStart(l));
 l["members"].erase(l["members"].begin()+1);refreshAutoFill(l);CHECK(l["auto_fill_target"]==11 && !operatorCanStart(l));CHECK(reject(l,request(11,true)));
 apply(l,request(11));apply(l,request(11,true));clockMs=150000;refreshAutoFill(l,true);CHECK(l["operator_bot_count"]==0 && l["auto_fill_started_ms"]==150000 && !operatorCanStart(l));
 CHECK(reject(l,request(200)));auto bad=request(0);bad["dw_auto_fill_bots"]=1;CHECK(reject(l,bad));bad=request(0);bad["dw_auto_fill_complete"]=1;CHECK(reject(l,bad));
 apply(l,request(0,false,false));CHECK(!l.contains("auto_fill_bots") && !l.contains("operator_bot_count") && operatorCanStart(l));
 CHECK(nativeBackendDocument(l)["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"]==0);
 auto manualPublished=l;manualPublished["operator_bot_count"]=uint64_t{1};CHECK(nativeBackendDocument(manualPublished)["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"]==1);
 auto manual=base();manual["operator_bots_requested"]=true;manual["operator_bot_count"]=uint64_t{11};CHECK(!slotsAvailable(manual,q));CHECK(reject(manual,request(0)));
 auto br=base();br["maximum_members"]=uint64_t{8};br["match_selection"]={{"squad_size",4u}};br["backend_doc"]["team_balance"]["squads"]={{"0",Json::array({uint64_t{1}})}};br["squad_fill"]={{"0",false}};CHECK(autoFillTarget(br)==4);
 br["squad_fill"]["0"]=true;CHECK(autoFillTarget(br)==7);br["backend_doc"]["player_id_to_slots"]["1"]=uint64_t{1};CHECK(autoFillTarget(br)==6);br["squad_fill"]["0"]=false;CHECK(autoFillTarget(br)==4);
 br["maximum_members"]=uint64_t{6};br["members"].push_back(uint64_t{2});br["backend_doc"]["team_balance"]["squads"]["1"]=Json::array({uint64_t{2}});br["squad_fill"]["1"]=false;CHECK(autoFillTarget(br)==0);apply(br,request(0));clockMs+=45000;apply(br,request(0,true));CHECK(operatorCanStart(br));Json newcomer{{"members",Json::array({uint64_t{3}})}};CHECK(!slotsAvailable(br,newcomer));br["squad_fill"]["0"]=true;CHECK(slotsAvailable(br,newcomer));
 std::puts("PASS: server ramp/completion, human admission, guest slots, BR noFill, retry, disable and migration policies"); return 0;
}
int main(){try{return exercise();}catch(const std::exception&e){std::printf("Exception: %s\n",e.what());return 2;}}
"""
    harness = harness.replace("@@BODIES@@", "\n".join(bodies)).replace(
        "@@UPDATE@@", update
    )
    vcvars = Path(
        r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
    )
    listing = subprocess.check_output(
        f'cmd /d /s /c "call "{vcvars}" >nul && set"', text=True
    )
    env = os.environ.copy()
    for line in listing.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            env[key.upper()] = value
    compiler = shutil.which("cl.exe", path=env["PATH"])
    assert compiler
    with tempfile.TemporaryDirectory(prefix="auto-fill-", dir=ROOT / "build") as tmp:
        folder = Path(tmp)
        cpp = folder / "fixture.cpp"
        image = folder / "fixture.exe"
        cpp.write_text(harness)
        common = [
            compiler,
            "/nologo",
            "/std:c++20",
            "/EHsc",
            "/DNOMINMAX",
            "/I" + str(ROOT / "src"),
        ]
        subprocess.run(
            common
            + [str(cpp), "/Fe:" + str(image), "/Fo:" + str(folder / "fixture.obj")],
            env=env,
            cwd=folder,
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run([str(image)], capture_output=True, text=True)
        print(result.stdout, result.stderr)
        if result.returncode:
            print(
                "\n".join(
                    f"{i+1}: {v}"
                    for i, v in enumerate(harness.splitlines())
                    if 263 <= i + 1 <= 269
                )
            )
        result.check_returncode()
        for name in ("matchmaking_services.cpp", "matchmaking_store.cpp"):
            subprocess.run(
                common
                + [
                    "/c",
                    str(ROOT / "src" / name),
                    "/Fo:" + str(folder / (name + ".obj")),
                ],
                env=env,
                cwd=folder,
                check=True,
                text=True,
            )
    inputs = [
        ROOT / "src/matchmaking_services.cpp",
        ROOT / "src/matchmaking_store.cpp",
        Path(__file__),
    ]
    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                component_result=result.stdout.strip(),
                translation_units_compiled=True,
                source_hashes={
                    str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs
                },
                game_tested=False,
                full_backend_build=False,
            ),
            indent=2,
        )
        + "\n"
    )
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
