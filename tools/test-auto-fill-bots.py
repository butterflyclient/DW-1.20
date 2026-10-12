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
    guarded_inputs = [ROOT / "src/matchmaking_services.cpp", ROOT / "src/matchmaking_store.cpp", Path(__file__)]
    input_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in guarded_inputs}
    source = (ROOT / "src/matchmaking_services.cpp").read_text()
    signatures = [
        "        bool lobbyCanWaitForStart(",
        "        bool lobbyWaitingForStart(",
        "        bool operatorCanStart(",
        "        unsigned nativeSquadLimit(",
        "        uint64_t reservedSquadPlaces(",
        "        uint64_t autoFillTarget(",
        "        void refreshAutoFill(",
        "        uint64_t occupiedSlots(const Json &members, const Json &slots)\n        {",
        "        std::optional<std::string> joiningSquad(",
        "        bool runningMatch(",
        "        void replaceRunningBots(",
        "        bool slotsAvailable(",
        "        Json nativeBackendDocument(",
    ]
    bodies = [extract(source, s) for s in signatures]
    store_source = (ROOT / "src/matchmaking_store.cpp").read_text()
    store_start = store_source.index('            if (state.contains("operator_bot_count"))')
    store_stop = store_source.index('            for (const auto *key : {"auto_fill_bots", "auto_fill_complete"})', store_start)
    store_validation = store_source[store_start:store_stop]
    start = source.index("                const auto submittedPhase = host.value(")
    stop = source.index('                if (host.contains("dw_bot_count"))', start)
    update = source[start:stop]
    migration_start = source.index(
        "refreshAutoFill(lobby, migration && lobbyWaitingForStart(lobby)"
    )
    migration_update = source[migration_start : source.index(";", migration_start) + 1]
    harness = r"""
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
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
void migrate(Json &lobby){const bool migration=true;@@MIGRATION@@}
void validateBotCount(const Json &state){using wire::require;@@STORE@@}
bool rejectsBotCount(Json state){try{validateBotCount(state);return false;}catch(const std::exception&){return true;}}
void check(bool b,int line){if(!b){std::printf("FAIL line%d\n",line);std::exit(1);}}
#define CHECK(x) check((x),__LINE__)
Json base(){return Json{{"update_id",uint64_t{1}},{"members",Json::array({uint64_t{1}})},{"maximum_members",uint64_t{12}},{"host_ready",true},{"expires",uint64_t{999999}},
 {"host_doc",{{"game_state",{{"state","intermission"}}}}},{"backend_doc",{{"player_id_to_slots",Json::object()}}}};}
uint64_t requestToken=0;
Json request(uint64_t count,bool complete=false,bool enabled=true){return Json{{"dw_auto_fill_request",++requestToken},{"game_state",{{"state","intermission"}}},{"dw_auto_fill_bots",enabled},{"dw_auto_fill_complete",complete},{"dw_bot_count",count}};}
bool reject(Json &l,Json h){auto copy=l;try{apply(copy,h);return false;}catch(const std::exception&){return true;}}
int exercise(){
 auto first=base();first["host_ready"]=false;
 CHECK(!lobbyWaitingForStart(first));
 CHECK(reject(first,request(1)) && reject(first,request(0,true)));
 apply(first,request(0));CHECK(first["auto_fill_bots"]==true && first["operator_bot_count"]==0 && !operatorCanStart(first));
 auto blocked=base();blocked["host_ready"]=false;blocked["backend_doc"]["private_lobby"]=Json::object();CHECK(reject(blocked,request(0)));
 blocked=base();blocked["host_ready"]=false;blocked["backend_doc"]["tournament"]=Json::object();CHECK(reject(blocked,request(0)));
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
 auto br=base();br["maximum_members"]=uint64_t{8};br["match_selection"]={{"squad_size",4u}};br["backend_doc"]["team_balance"]["squads"]={{"0",Json::array({uint64_t{1}})}};br["squad_fill"]={{"0",false}};CHECK(autoFillTarget(br)==7);
 br["squad_fill"]["0"]=true;CHECK(autoFillTarget(br)==7);br["backend_doc"]["player_id_to_slots"]["1"]=uint64_t{1};CHECK(autoFillTarget(br)==6);br["squad_fill"]["0"]=false;CHECK(autoFillTarget(br)==6);
 br["backend_doc"]["player_id_to_slots"].erase("1");br["maximum_members"]=uint64_t{6};br["members"].push_back(uint64_t{2});br["backend_doc"]["team_balance"]["squads"]["1"]=Json::array({uint64_t{2}});br["squad_fill"]["1"]=false;CHECK(autoFillTarget(br)==4);apply(br,request(0));clockMs+=45000;apply(br,request(4));apply(br,request(4,true));CHECK(operatorCanStart(br));Json newcomer{{"members",Json::array({uint64_t{3}})}};CHECK(slotsAvailable(br,newcomer));
 // Two solo No Fill parties consume two protected squads, while every
 // remaining playlist player position can be occupied by native bots.
 auto full=br;full["members"]=Json::array({uint64_t{1},uint64_t{2}});full["maximum_members"]=uint64_t{152};full["auto_fill_complete"]=false;
 CHECK(reservedSquadPlaces(full)==6 && autoFillTarget(full)==150);
 refreshAutoFill(full);full["operator_bot_count"]=uint64_t{150};full["auto_fill_complete"]=true;
 auto fullDoc=nativeBackendDocument(full);CHECK(fullDoc["team_balance"]["teams"].size()==40);
 CHECK(fullDoc["ruleset_payload"]["dvar_overrides"]["party_teamCount"]==40);
 CHECK(fullDoc["ruleset_payload"]["dvar_overrides"]["replay_dw_autoFillBotTarget"]==150);
 CHECK(fullDoc["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"]==150);
 CHECK(fullDoc["ruleset_payload"]["dvar_overrides"]["replay_dw_reservedSquads"].get<std::string>().back()=='3');
 full["backend_doc"]["team_balance"]["squads"]["2"]=Json::array();full["squad_fill"]["2"]=false;
 CHECK(reservedSquadPlaces(full)==6 && autoFillTarget(full)==150);
 CHECK(nativeBackendDocument(full)["ruleset_payload"]["dvar_overrides"]["replay_dw_reservedSquads"].get<std::string>().back()=='3');
 auto started=full["auto_fill_started_ms"];migrate(full);CHECK(full["auto_fill_complete"]==true && full["operator_bot_count"]==150 && full["auto_fill_started_ms"]==started);
 full["host_doc"]["game_state"]["state"]="ingame";full["members"].erase(full["members"].begin()+1);full["backend_doc"]["team_balance"]["squads"]["1"]=Json::array();
 refreshAutoFill(full);migrate(full);CHECK(full["auto_fill_target"]==150 && full["operator_bot_count"]==150 && full["auto_fill_complete"]==true && full["auto_fill_started_ms"]==started);
 auto crowded=base();crowded["maximum_members"]=uint64_t{200};crowded["auto_fill_bots"]=true;crowded["match_selection"]={{"squad_size",2u}};crowded["members"]=Json::array();
 for(unsigned group=0;group<63;++group){const auto key=std::to_string(group);crowded["members"].push_back(uint64_t(group+1));crowded["backend_doc"]["team_balance"]["squads"][key]=Json::array({uint64_t(group+1)});crowded["squad_fill"][key]=false;}
 Json crowdJoin{{"members",Json::array({uint64_t{1000}})}};
 CHECK(autoFillTarget(crowded)==0 && reservedSquadPlaces(crowded)==63 && !slotsAvailable(crowded,crowdJoin));
 crowded["backend_doc"]["team_balance"]["squads"]["62"]=Json::array();crowded["members"].erase(crowded["members"].begin()+62);CHECK(autoFillTarget(crowded)==2 && slotsAvailable(crowded,crowdJoin));
 // A running full roster replaces bots once for each new real slot.
 auto jip=base();jip["host_doc"]["game_state"]["state"]="in_game";jip["operator_bots_requested"]=true;jip["operator_bot_count"]=uint64_t{11};
 CHECK(slotsAvailable(jip,q));jip["members"].push_back(uint64_t{2});replaceRunningBots(jip,1);CHECK(jip["operator_bot_count"]==10 && jip["maximum_members"]==12);
 replaceRunningBots(jip,2);CHECK(jip["operator_bot_count"]==10); // retry
 Json guest{{"members",Json::array({uint64_t{3}})},{"slots",{{"3",uint64_t{1}}}}};CHECK(slotsAvailable(jip,guest));
 jip["members"].push_back(uint64_t{3});jip["backend_doc"]["player_id_to_slots"]["3"]=uint64_t{1};replaceRunningBots(jip,2);CHECK(jip["operator_bot_count"]==8);
 guest["slots"]["3"]=uint64_t{0};CHECK(!slotsAvailable(jip,guest));
 auto automatic=jip;automatic["auto_fill_bots"]=true;automatic["auto_fill_complete"]=true;automatic["auto_fill_target"]=uint64_t{8};automatic["auto_fill_started_ms"]=uint64_t{123};automatic["auto_fill_request"]=uint64_t{7};
 automatic["members"].push_back(uint64_t{4});replaceRunningBots(automatic,4);refreshAutoFill(automatic);migrate(automatic);
 CHECK(automatic["operator_bot_count"]==7 && automatic["auto_fill_target"]==7 && automatic["auto_fill_complete"]==true && automatic["auto_fill_started_ms"]==123 && automatic["auto_fill_request"]==7);
 auto humans=base();humans["host_doc"]["game_state"]["state"]="in_game";humans["maximum_members"]=uint64_t{1};CHECK(!slotsAvailable(humans,q));CHECK(slotsAvailable(humans,Json{{"members",Json::array({uint64_t{1}})}}));
 auto party=br;party["host_doc"]["game_state"]["state"]="in_game";Json oversized{{"members",Json::array({uint64_t{10},uint64_t{11},uint64_t{12},uint64_t{13},uint64_t{14}})}};CHECK(!slotsAvailable(party,oversized));
 auto anchored=br;anchored["host_doc"]["game_state"]["state"]="in_game";anchored["operator_bot_count"]=uint64_t{4};
 Json ownParty{{"members",Json::array({uint64_t{1},uint64_t{3}})},{"team_balance",{{"lock_squad",true}}}};
 CHECK(slotsAvailable(anchored,ownParty) && joiningSquad(anchored,ownParty,lobbySlots(anchored))==std::optional<std::string>{"0"});
 CHECK(joiningSquad(anchored,newcomer,lobbySlots(anchored))==std::optional<std::string>{"2"});
 auto limited=crowded;limited["host_doc"]["game_state"]["state"]="in_game";limited["operator_bot_count"]=uint64_t{2};crowdJoin["team_balance"]={{"lock_squad",true}};
 CHECK(!slotsAvailable(limited,crowdJoin));crowdJoin["team_balance"]["lock_squad"]=false;CHECK(slotsAvailable(limited,crowdJoin));
 auto ordinary=base();ordinary["host_doc"]["game_state"]["state"]="in_game";ordinary["members"].push_back(uint64_t{2});replaceRunningBots(ordinary,1);CHECK(!ordinary.contains("operator_bot_count"));
 auto lastBot=jip;lastBot["operator_bot_count"]=uint64_t{1};lastBot["members"].push_back(uint64_t{99});replaceRunningBots(lastBot,4);CHECK(lastBot["operator_bot_count"]==0 && lastBot["operator_bots_requested"]==true);
 auto countState=base();countState["operator_bots_requested"]=true;countState["operator_bot_count"]=uint64_t{0};CHECK(!rejectsBotCount(countState));
 countState["host_doc"]["game_state"]["state"]="in_game";CHECK(!rejectsBotCount(countState));
 countState["operator_bots_requested"]=false;CHECK(rejectsBotCount(countState));countState["operator_bots_requested"]=true;
 countState["operator_bot_count"]=uint64_t{200};CHECK(rejectsBotCount(countState));countState["operator_bot_count"]=uint64_t{1};CHECK(!rejectsBotCount(countState));
 countState["host_doc"]["game_state"]["state"]="intermission";countState["auto_fill_bots"]=true;countState["operator_bot_count"]=uint64_t{0};CHECK(!rejectsBotCount(countState));
 CHECK(nativeBackendDocument(automatic)["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"]==7);
 std::puts("PASS: running JIP manual/auto bot replacement, guest reservations, duplicates, human cap, oversized party, migration; ramp/completion, No Fill 150 bots plus 2 humans in 40 groups, empty squads, 63-group bound, running roster and completed migration"); return 0;
}
int main(){try{return exercise();}catch(const std::exception&e){std::printf("Exception: %s\n",e.what());return 2;}}
"""
    harness = (
        harness.replace("@@BODIES@@", "\n".join(bodies))
        .replace("@@UPDATE@@", update)
        .replace("@@MIGRATION@@", migration_update)
        .replace("@@STORE@@", store_validation)
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
            failure_line = (
                int(result.stdout.split("FAIL line", 1)[1].splitlines()[0])
                if "FAIL line" in result.stdout
                else 1
            )
            print(
                "\n".join(
                    f"{i+1}: {v}"
                    for i, v in enumerate(harness.splitlines())
                    if failure_line - 2 <= i + 1 <= failure_line + 2
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
    for p in guarded_inputs:
        assert hashlib.sha256(p.read_bytes()).hexdigest() == input_hashes[str(p)], str(p)
    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                component_result=result.stdout.strip(),
                translation_units_compiled=True,
                source_hashes=input_hashes,
                source_inputs_unchanged=True,
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
