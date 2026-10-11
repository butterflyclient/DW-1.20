"""Compile daily predicates/state/delivery logic against original Replay parser packets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base_path = ROOT / "validation/20261009-challenge-event-parser.json"
    mp_path = ROOT / "validation/20261011-replay-mp-mission-events.json"
    base, mp = [json.loads(path.read_bytes()) for path in (base_path, mp_path)]
    normal = next(row for row in mp["cases"] if row.get("name") == "kill" and
                  "MOD_RIFLE_BULLET," in row.get("input", "") and (row["values"][5] >> 16 & 1))
    head = next(row for row in mp["cases"] if row.get("name") == "kill" and "MOD_HEAD_SHOT," in row.get("input", ""))
    melee = next(row for row in mp["cases"] if row.get("name") == "kill" and "MOD_MELEE," in row.get("input", ""))
    packets = [row["values"] for row in (normal, head, melee)]
    assert all(row["accepted"] and row["parameter_count"] == 7 for row in (normal, head, melee))
    assert packets[1][6] >> 16 & 65535 == 9 and packets[2][6] >> 16 & 65535 == 8
    arrays = "\n".join("std::array<uint64_t,7> " + name + " = {" + ",".join(str(value)+"ULL" for value in packet)+"};"
                       for name, packet in zip(("normal", "head", "melee"), packets))
    harness = r'''
#include "quest_services.h"
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
using Json = nlohmann::json;
using namespace services;
const char *stage="assignment";
@@PACKETS@@
void check(bool ok, unsigned line) { if (!ok) { std::printf("Daily fixture failed at line %u\n",line); std::exit(1); } }
#define require(condition) check((condition),__LINE__)
Json event(const std::array<uint64_t,7> &packet, uint64_t time) {
    Json values{{"gamemode",uint64_t{2}}, {"version",uint64_t{1}}};
    for (unsigned i=0;i<7;++i) values["Param"+std::to_string(i)] = packet[i];
    return Json{{"name","kill"},{"timestamp",time},{"values",values}};
}
Json &state(Json &states, unsigned id) {
    for (auto &row : states) if (row.at("id") == id) return row;
    throw std::runtime_error("Missing daily state");
}
int exercise() {
    const uint64_t now=10*86400+100;
    Json states=Json::array({{{"id",uint64_t{1501}},{"name","preserved"},{"kind",uint64_t{15}},
                            {"status",uint64_t{2}},{"progress",uint64_t{4}},{"target",uint64_t{5}}}});
    const auto unrelated=states[0];
    require(synchronizeReplayDailies(states,now));
    require(states.size()==10 && states[0]==unrelated);
    for (const auto &definition: replayDailyChallenges) {
        const auto &row=state(states,definition.id);
        require(row.at("progress")==0 && row.at("status")==1 && row.at("target")==definition.target);
        require(definition.sourceFields.size()==13);
    }
    const auto initial=states;
    require(!synchronizeReplayDailies(states,now+1) && states==initial);
    states=Json::parse(states.dump());
    require(!synchronizeReplayDailies(states,now+1));
    Json kills=Json::array();
    for(unsigned i=0;i<20;++i)kills.push_back(event(normal,now+1));
    for(unsigned i=0;i<5;++i)kills.push_back(event(head,now+1));
    for(unsigned i=0;i<3;++i)kills.push_back(event(melee,now+1));
    std::vector<ReplayQuestEventContext> contexts(kills.size(), {0,now+1});
    auto earned=advanceReplayDailies(states,kills,contexts,now+1);
    require(earned.xp==6000 && earned.items.empty() && earned.updates.size()==3);
    for(unsigned id:{1797u,1798u,1799u})
        require(state(earned.states,id).at("progress")==state(earned.states,id).at("target") &&
                state(earned.states,id).at("status")==3 && state(earned.states,id).at("completionCount")==1);
    for(const auto &definition:replayDailyChallenges)if(definition.kind!=12)
        require(state(earned.states,definition.id).at("progress")==0);
    auto repeat=advanceReplayDailies(earned.states,kills,contexts,now+1);
    require(!repeat.xp && repeat.updates.empty() && repeat.states==earned.states);
    platform::LobbyIdentity id;id.userId=77;
    stage="delivery";
    auto deliveries=replayDailyUpdates(id,"5800",earned);
    require(deliveries.size()==3);
    for(const auto &delivery:deliveries) {
        stage="delivery validity";
        require(replayQuestDeliveryValid(earned.states,delivery));
        stage="delivery header";
        wire::Reader reader{delivery.payload};
        require(reader.u32()==67 && reader.u8()==1 && reader.u64()==77);
        stage="delivery accounts";
        require(reader.text()=="uno" && reader.text()=="5800");
        stage="delivery counts";
        require(reader.value<int32_t>(7)==1 && reader.u32()==1 && reader.value<int32_t>(7)==1);
        stage="delivery body";
        const auto body=reader.text(4096);
        stage="delivery end";
        require(reader.offset==reader.data.size());
        auto payload=Json::parse(body);
        require(payload.at("kind")==12 && payload.at("reason")=="completed" && payload.at("completionTimestamp")==now+1);
    }
    stage="refresh";
    auto refreshed=replayDailyUpdates(id,"5800",earned,true);
    require(refreshed.size()==3);
    stage="invalid admission";
    for(unsigned fixture=0;fixture<10;++fixture) {
        auto rejected=event(normal,now+1);ReplayQuestEventContext context{0,now+1};
        if(fixture==0)context.category=std::nullopt;
        if(fixture==1)context.category=1;
        if(fixture==2)rejected["values"]["gamemode"]=uint64_t{8};
        if(fixture==3)rejected["values"]["version"]=uint64_t{0};
        if(fixture==4)rejected["values"].erase("Param6");
        if(fixture==5)rejected["timestamp"]=now-1;
        if(fixture==6)rejected["timestamp"]=now+2;
        if(fixture==7)context.activationCutoff=now-1;
        if(fixture==8)rejected["name"]="death";
        if(fixture==9)rejected["values"]["Param5"]=uint64_t{2}<<16;
        const std::array<ReplayQuestEventContext,1> ownership={context};
        auto result=advanceReplayDailies(initial,Json::array({rejected}),ownership,now+1);
        require(!result.xp && result.updates.empty() && result.states==initial);
    }
    stage="rollover";
    auto nextDay=earned.states;
    const uint64_t boundary=11*86400;
    require(synchronizeReplayDailies(nextDay,boundary));
    require(nextDay[0]==unrelated && state(nextDay,1797).at("progress")==0);
    for(const auto &delivery:deliveries)require(!replayQuestDeliveryValid(nextDay,delivery));
    auto stale=advanceReplayDailies(nextDay,kills,contexts,boundary);
    require(stale.updates.empty() && !stale.xp && stale.states==nextDay);
    require(!synchronizeReplayDailies(nextDay,boundary+1));
    auto nextKill=Json::array({event(normal,boundary+1)});
    const std::array<ReplayQuestEventContext,1> nextContext={ReplayQuestEventContext{0,boundary+1}};
    require(advanceReplayDailies(nextDay,nextKill,nextContext,boundary+1).updates.size()==1);
    std::puts("PASS: daily native metadata, zero assignment, MP earning/rewards, exclusions, admission, cycle and event67 contracts");
    return 0;
}
int main() { try { return exercise(); } catch (const std::exception &error) { std::printf("FAIL at %s: %s\n",stage,error.what()); return 1; } }
'''.replace("@@PACKETS@@", arrays)
    vcvars=Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")
    listing=subprocess.check_output(f'cmd /d /s /c "call "{vcvars}" >nul && set"',text=True)
    environment=dict(os.environ)
    for line in listing.splitlines():
        key,separator,value=line.partition("=")
        if separator and key.upper() in ("PATH","INCLUDE","LIB","LIBPATH"):environment[key.upper()]=value
    compiler=shutil.which("cl.exe",path=environment["PATH"])
    assert compiler
    (ROOT/"build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="daily-fixture-",dir=ROOT/"build") as temporary:
        folder=Path(temporary); cpp=folder/"daily.cpp";image=folder/"daily.exe";cpp.write_text(harness)
        command=[compiler,"/nologo","/std:c++20","/EHsc","/O2","/DNOMINMAX","/I"+str(ROOT/"src"),str(cpp),
                 str(ROOT/"src/quest_services.cpp"),str(ROOT/"src/crypto.cpp"),"/Fe:"+str(image),"/link","bcrypt.lib"]
        subprocess.run(command,cwd=folder,env=environment,check=True)
        result=subprocess.run([str(image)],capture_output=True,text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        subprocess.run([compiler,"/nologo","/std:c++20","/EHsc","/DNOMINMAX","/c",str(ROOT/"src/achievement_services.cpp"),
                        "/Fo:"+str(folder/"achievement.obj")],cwd=folder,env=environment,check=True)
    inputs=(ROOT/"src/achievement_services.cpp",ROOT/"src/quest_services.cpp",ROOT/"src/quest_services.h",
            ROOT/"src/replay_daily_challenges.h",base_path,mp_path)
    proof=dict(passed=True,native_game_verified=False,full_backend_build_verified=False,
               source_sha256={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
               parser_packets={name:row for name,row in zip(("normal","headshot","melee"),(normal,head,melee))},
               component_result=result.stdout.strip(), backend_achievement_translation_unit_compiled=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(proof,indent=2)+"\n")
    print(result.stdout.strip())


if __name__=="__main__":main()
