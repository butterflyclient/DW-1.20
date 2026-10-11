"""Check daily assignment/earning transactions on a disposable encrypted backend."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request

from native_wire_client import NativeClient, binary, fields, integer, structure, text, u32, u64
from progression_delivery_fixtures import decode_event67

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    server=args.server.resolve(strict=True)
    packets=json.loads((ROOT/"validation/20261011-replay-mp-mission-events.json").read_bytes())["cases"]
    selected=[next(row for row in packets if row.get("name")=="kill" and cause in row.get("input","")
                   and row["values"][5]>>16 & 1)
              for cause in ("MOD_RIFLE_BULLET,","MOD_HEAD_SHOT,","MOD_MELEE,")]
    flags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
    checks=[]
    with tempfile.TemporaryDirectory(prefix="daily-wire-",dir=ROOT/"data") as temporary:
        fixture=Path(temporary);data=fixture/"data";data.mkdir()
        shutil.copy2(ROOT/"data/replay-traffic-kdf.bin",data)
        catalog=runpy.run_path(str(ROOT/"tools/prepare-playlist-catalog.py"))["prepare"](data,["mp_shipment"],1)
        for profile in ("daily-host","daily-peer"):
            subprocess.run([str(server),str(data),"--provision-profile",profile,profile],
                           stdout=subprocess.DEVNULL,check=True,creationflags=flags)
        offset=None
        for candidate in range(22400,22600):
            probes=[]
            try:
                for port in (8085,8443,3075):
                    probe=socket.socket();probes.append(probe);probe.bind(("127.0.0.1",candidate+port))
                offset=candidate;break
            except OSError:pass
            finally:
                for probe in probes:probe.close()
        assert offset is not None
        log=(fixture/"server.log").open("wb")
        process=subprocess.Popen([str(server),str(data),"--port-offset",str(offset)],
                                 stdout=log,stderr=subprocess.STDOUT,creationflags=flags)

        def query(client,kind,context="5800"):
            raw=client.task(125,3,structure(text(1,context)+integer(2,kind)+integer(3,100)+text(4,"")+integer(8,0)))
            return [fields(row) for row in fields(raw).get(1,[])]

        def state_path(client):return data/"achievements/5800/5800"/str(client.user)/"states.json"
        def state_snapshot(client):return json.loads(state_path(client).read_bytes())
        def journal(client):return json.loads(state_path(client).with_name("events.json").read_bytes())
        def ordinary(value):return b"\x10"+value.encode()+b"\0"
        def documents(raw):
            out=[]
            while raw:
                assert raw[0]==16;end=raw.index(0,1);out.append(json.loads(raw[1:end]));raw=raw[end+1:]
            return out
        def receive(client):return (2,client.pushes.pop(0)) if client.pushes else client.receive()
        def receive_lobby(client,expected):
            while True:
                kind,packet=receive(client)
                if packet.startswith(u32(67)):
                    assert decode_event67(packet,client.user)[2]["kind"]==0
                    continue
                assert kind==2 and packet.startswith(u32(expected));return packet
        def event(packet,timestamp):
            value=text(1,"kill")+integer(2,timestamp)+integer(4,0)
            values={f"Param{i}":word for i,word in enumerate(packet["values"])}
            values.update(version=1,gamemode=2)
            for key,word in values.items():value+=binary(3,text(1,key)+integer(2,word))
            return value
        def send(client,request,events,context="5800"):
            payload=structure(text(1,context)+b"".join(binary(2,row) for row in events)+text(3,request))
            assert client.task(125,1,payload)==b"";return payload

        try:
            for _ in range(100):
                assert process.poll() is None
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{8085+offset}/health",timeout=.3).close();break
                except OSError:time.sleep(.05)
            else:raise RuntimeError("Daily backend did not become ready")
            with NativeClient(fixture,profile="daily-host",port_offset=offset) as host, \
                 NativeClient(fixture,profile="daily-peer",port_offset=offset) as peer:
                # Alias-first reads enroll the same canonical schedule, never
                # another per-context progress/reward owner.
                alias_initial=query(host,12,"iw8")
                assert len(alias_initial)==3 and all(row[3]==[0] for row in alias_initial)
                for kind in (12,27,30):
                    rows=query(host,kind)
                    assert len(rows)==3 and all(row[2]==[kind] and row[3]==[0] and row[4][0]>0 and row[5]==[1] for row in rows)
                baseline=state_path(host).read_bytes()
                query(host,12);assert state_path(host).read_bytes()==baseline
                assert all(row["progress"]==0 for row in state_snapshot(host))
                query(peer,12);assert all(row["progress"]==0 for row in state_snapshot(peer))
                checks.append("Nine canonical daily states, native three-per-kind pages, zero progress and independent accounts")
                timestamp=int(time.time())
                send(host,"daily-no-public",[event(selected[0],timestamp)])
                assert state_path(host).read_bytes()==baseline
                tokens=[]
                for client in (host,peer):
                    info={"dedicated_server":{"build_name":"daily-fixture"},
                          "listen_server":{"local_address":base64.b64encode(bytes(84)).decode(),
                                           "security_id":base64.b64encode(os.urandom(8)).decode(),
                                           "security_key":base64.b64encode(os.urandom(16)).decode()},
                          "game_state":{"map_packs":["MP_ORIGINAL_MAPS"]},"hardware":"pc"}
                    assert client.task(145,2,ordinary(json.dumps(info)),structured=False)==b""
                    tokens.append(struct.unpack_from("<Q",client.task(145,3,b"",structured=False),1)[0])
                allocation={"members":[host.user,peer.user],"tokens":tokens,
                            "lobby_slots":{"min":1,"max":4},"team_balance":{"num_teams":2},
                            "ruleset_payload":{"filter":{"playlist_id":1,"netcode_version":66514,
                                                        "playlist_version":catalog["version"]}}}
                documents(host.task(145,18,ordinary(json.dumps(allocation)),structured=False))
                created=receive_lobby(host,2005);lobby=struct.unpack_from("<Q",created,15)[0]
                docs=documents(created[32:]);docs[0]["game_state"]["state"]="in_game"
                assert host.task(145,15,u64(lobby)+u64(docs[1]["update_id"])+ordinary(json.dumps(docs[0])),structured=False)==b"\x01\x01"
                receive_lobby(host,2006);receive_lobby(peer,2001)
                timestamp=int(time.time())
                events=[event(selected[0],timestamp)]*20+[event(selected[1],timestamp)]*5+[event(selected[2],timestamp)]*3
                send(host,"daily-alias-first",events,"iw8")
                assert state_path(host).read_bytes()==baseline
                assert all(row[3]==[0] for row in query(host,12,"iw8"))
                alias_folder=data/"achievements/5800/iw8"/str(host.user)
                assert json.loads((alias_folder/"events.json").read_bytes())["player_xp"]==0
                if (alias_folder/"states.json").exists():
                    assert not any(row.get("kind") in (12,27,30) for row in json.loads((alias_folder/"states.json").read_bytes()))
                payload=send(host,"daily-completion",events)
                stored=state_snapshot(host);completed=[row for row in stored if row["kind"]==12]
                assert len(completed)==3 and all(row["status"]==3 and row["progress"]==row["target"] and row["completionCount"]==1 for row in completed)
                assert journal(host)["player_xp"]==6000
                assert all(row[5]==[3] and row[3]==row[4] for row in query(host,12,"iw8"))
                send(host,"daily-alias-after",events,"iw8")
                assert json.loads((alias_folder/"events.json").read_bytes())["player_xp"]==0
                assert all(row["progress"]==0 and row["status"]==1 for row in stored if row["kind"] in (27,30))
                daily_notifications=[]
                while len(daily_notifications)<3:
                    kind,packet=receive(host);assert kind==2
                    update=decode_event67(packet,host.user)[2]
                    if update["kind"]==12:
                        assert update["reason"]=="completed" and update["completionTimestamp"]==timestamp
                        daily_notifications.append(update)
                    else:assert update["kind"]==0
                before=state_path(host).read_bytes();before_journal=state_path(host).with_name("events.json").read_bytes()
                assert host.task(125,1,payload)==b""
                assert state_path(host).read_bytes()==before and state_path(host).with_name("events.json").read_bytes()==before_journal
                send(host,"daily-post-completion",events)
                assert journal(host)["player_xp"]==6000 and state_path(host).read_bytes()==before
                assert all(row["progress"]==0 for row in state_snapshot(peer))
                checks.append("Original parser packets earn only public MP kills/headshots/melee; XP and event67 completion occur once; receipt retries preserve state")
                checks.append("Alias-first iw8 enrollment and alias public reports mirror canonical 5800 progress without consuming actions or awarding duplicate daily XP")
                # Simulate an older durable cycle only inside this disposable store.
                old=state_snapshot(host)
                for row in old:
                    if row.get("kind") in (12,27,30):row["dailyCycle"]-=1
                state_path(host).write_text(json.dumps(old))
                query(host,12)
                reset=state_snapshot(host)
                assert all(row["progress"]==0 and row["status"]==1 for row in reset if row.get("kind") in (12,27,30))
                assert journal(host)["player_xp"]==6000
                reset_bytes=state_path(host).read_bytes();query(host,12)
                assert state_path(host).read_bytes()==reset_bytes
                # Previous-day cached packets cannot earn after replacement.
                old_timestamp=(int(time.time())//86400)*86400-1
                send(host,"daily-old-cycle",[event(selected[1],old_timestamp)])
                assert state_path(host).read_bytes()==reset_bytes and journal(host)["player_xp"]==6000
                checks.append("Durable UTC cycle replacement resets only daily state; repeated reads and previous-day cached reports cannot award again")
                # Match resetAchievementProgression's preserved receipt history,
                # only in this disposable store; the production reset is untouched.
                old_journal=journal(host)
                fresh=dict(schema=1,next=old_journal["next"],events=[],requests=old_journal["requests"],
                           player_xp=0,weapon_xp={},matches={})
                state_path(host).with_name("events.json").write_text(json.dumps(fresh))
                state_path(host).write_text("[]")
                assert host.task(125,1,payload)==b""
                assert journal(host)["player_xp"]==0 and state_snapshot(host)==[]
                query(host,12)
                assert host.task(125,1,payload)==b""
                assert journal(host)["player_xp"]==0 and all(row["progress"]==0 for row in state_snapshot(host))
                checks.append("Accepted daily completion retry after durable reset preserves zero XP and zero/new pending states without regranting the old award")
        finally:
            process.terminate();process.wait(timeout=10);log.close()
    proof=dict(passed=True,server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
               checks=checks,native_game_verified=False,live_profile_changed=False,fixture_cleaned=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(proof,indent=2)+"\n")
    print(f"PASS: {len(checks)} encrypted daily contract groups")


if __name__=="__main__":main()
