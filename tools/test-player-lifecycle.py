"""Execute extracted channel recovery/presence revision helpers; no game/server.

Storage failure is modeled. The channel_membership_fixtures.py native-wire case
separately exercises real atomic file publication and endpoint reconnects.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def extract(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    channel = (ROOT / "src/channel_services.cpp").read_text()
    social = (ROOT / "src/social_services.cpp").read_text()
    store = (ROOT / "src/channel_store.cpp").read_text()
    # Guard actual call sites as well as executing their source-linked helpers.
    assert channel.index("auto recovered = retryDisconnects(directory, id.titleId);") < channel.index(
        'auto state = channel_store::load(path, id.titleId);'
    )
    assert "reclaimPresenceRevisions();" in extract(social, "std::vector<Delivery> socialDisconnected(")
    presence = extract(social, "Reply presence(")
    assert "reclaimPresenceRevisions();" in presence
    chunks = "\n".join(extract(channel, marker) for marker in (
        "Delivery context(", "wire::Bytes membershipPacket(", "void notifyMembership(",
        "bool removeMember(", "std::vector<Delivery> retryDisconnects(",
        "std::vector<Delivery> disconnectChannels(", "bool channelDeliveryValid(",
    ))
    revisions = "\n".join(extract(social, marker) for marker in (
        "uint64_t revisePresence(", "void reclaimPresenceRevisions(",
        "bool socialDeliveryValid(",
    ))
    advance = extract(store, "void require(bool valid)") + "\n" + extract(store, "uint32_t advance(")
    channel_globals = channel[channel.index("std::set<std::pair<uint32_t, uint64_t>> pendingDisconnects;"):
                              channel.index("uint64_t now()")]
    social_globals = social[social.index("std::map<std::tuple<uint32_t, std::string, uint64_t>, std::vector<Json>> subscriptions;"):
                            social.index("constexpr uint32_t get =")]
    harness = r'''
#include "channel_services.h"
#include "channel_store.h"
#include "social_services.h"
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <tuple>
using Json = nlohmann::json;
namespace channel_store {
Json disk;
bool blocked = false;
Json load(const std::filesystem::path &, uint32_t) { return disk; }
void save(const std::filesystem::path &, uint32_t, const Json &state) {
    if (blocked) throw std::runtime_error("modeled atomic publication failure");
    disk = state;
}
@@ADVANCE@@
}
namespace services {
@@CHANNEL_GLOBALS@@
@@SOCIAL_GLOBALS@@
@@CHANNEL@@
@@SOCIAL@@
}
void check(bool passed, const char *issue) {
    if (!passed) throw std::runtime_error(issue);
}
int main(int argc, char **argv) {
    using namespace services;
    check(argc == 2, "fixture path");
    const std::filesystem::path directory = argv[1];
    std::filesystem::create_directories(directory / "channels");
    std::ofstream(directory / "channels/5800.json") << "{}";
    channel_store::disk = {{"schema", 1}, {"title", 5800}, {"channels", {
        {"party:7", {{"category", "party"}, {"id", uint64_t{7}}, {"owner", uint64_t{1}},
                     {"created", uint64_t{1}}, {"revision", uint32_t{2}}, {"members", {
                        {"1", {{"name", "Owner"}, {"expires", uint64_t{9999999999}}, {"generation", uint32_t{1}}}},
                        {"2", {{"name", "Peer"}, {"expires", uint64_t{9999999999}}, {"generation", uint32_t{2}}}}
                     }}}}
    }}};
    const auto original = channel_store::disk;
    channel_store::blocked = true;
    bool failed = false;
    try { (void)disconnectChannels(directory, 5800, 2); } catch (...) { failed = true; }
    check(failed && channel_store::disk == original && pendingDisconnects.contains({5800, 2}),
          "failed cleanup loses its retirement marker or publishes a mutation");
    Delivery oldJoin;
    oldJoin.user = 1; oldJoin.channelCategory = "party"; oldJoin.channelId = 7;
    oldJoin.channelMember = 2; oldJoin.channelEvent = 24;
    oldJoin.channelMemberGeneration = 2; oldJoin.channelRecipientGeneration = 1;
    check(!channelDeliveryValid(directory, 5800, oldJoin), "retired lifetime retains push authority");
    failed = false;
    try { (void)retryDisconnects(directory, 5800); } catch (...) { failed = true; }
    check(failed && channel_store::disk == original && pendingDisconnects.contains({5800, 2}),
          "failed reconnect reconciliation discards pending retirement");
    channel_store::blocked = false;
    const auto departures = retryDisconnects(directory, 5800);
    check(departures.size() == 1 && departures[0].channelEvent == 25 &&
          channelDeliveryValid(directory, 5800, departures[0]) && pendingDisconnects.empty(),
          "recovered cleanup fails exact leave validation");
    auto &row = channel_store::disk["channels"]["party:7"];
    check(!row["members"].contains("2") && row["members"].contains("1"),
          "cleanup retains retired peer or removes unaffected owner");
    const auto freshGeneration = channel_store::advance(row);
    row["members"]["2"] = {{"name", "Peer"}, {"expires", uint64_t{9999999999}}, {"generation", freshGeneration}};
    check(freshGeneration > 2 && !channelDeliveryValid(directory, 5800, oldJoin) &&
          !channelDeliveryValid(directory, 5800, departures[0]), "old generations revive after real rejoin");
    oldJoin.channelMemberGeneration = freshGeneration;
    check(channelDeliveryValid(directory, 5800, oldJoin), "fresh generation cannot publish");
    std::cout << "PASS: failed channel cleanup retries atomically, rejects retired authority, preserves unrelated members, and invalidates old generations\n";

    const PresenceScope scope{5800, "iw8", 2};
    const PresenceScope watcher{5800, "iw8", 1};
    subscriptions[watcher] = {Json{{"userID", uint64_t{2}}, {"accountType", "uno"}}};
    const auto onlineRevision = revisePresence(scope);
    publishedOnline.insert(scope);
    Delivery online; online.presenceUser = 2; online.presenceContext = "iw8";
    online.presenceRevision = onlineRevision;
    publishedOnline.erase(scope);
    Delivery offline = online; offline.presenceRevision = revisePresence(scope);
    reclaimPresenceRevisions();
    check(!socialDeliveryValid(5800, online) && socialDeliveryValid(5800, offline),
          "reclamation drops final watched offline packet or keeps old online packet");
    subscriptions.erase(watcher);
    reclaimPresenceRevisions();
    check(presenceRevisions.empty() && !socialDeliveryValid(5800, offline),
          "unwatched disconnected scope remains allocated or old packet stays valid");
    publishedOnline.insert(scope);
    Delivery reconnected = offline; reconnected.presenceRevision = revisePresence(scope);
    check(reconnected.presenceRevision > offline.presenceRevision &&
          socialDeliveryValid(5800, reconnected) && !socialDeliveryValid(5800, offline),
          "scope reuse revives a stale offline packet");
    for (unsigned i = 0; i < 70000; ++i) {
        const PresenceScope temporary{5800, std::to_string(i), 3};
        (void)revisePresence(temporary);
        reclaimPresenceRevisions();
    }
    check(presenceRevisions.size() == 1 && socialDeliveryValid(5800, reconnected),
          "historical presence scopes exhaust capacity or reclaim active publication");
    subscriptions[{5800, "iw8", 9}] = {Json{{"userID", uint64_t{2}}, {"accountType", "uno"}}};
    publishedOnline.erase(scope);
    reclaimPresenceRevisions();
    check(presenceRevisions.contains(scope), "an independent subscriber loses final offline authority");
    subscriptions.clear();
    reclaimPresenceRevisions();
    check(presenceRevisions.empty(), "final subscriber cleanup leaks offline revisions");
    std::cout << "PASS: watched offline delivery survives, stale pushes stay invalid after scope reuse, and 70,000 historical scopes reclaim without exhausting capacity\n";
}
'''
    for key, value in (('ADVANCE', advance), ('CHANNEL_GLOBALS', channel_globals),
                       ('SOCIAL_GLOBALS', social_globals), ('CHANNEL', chunks), ('SOCIAL', revisions)):
        harness = harness.replace('@@' + key + '@@', value)
    compiler = shutil.which("clang++") or shutil.which("g++")
    if not compiler:
        compiler = r"C:\Program Files\LLVM\bin\clang++.exe"
    (ROOT / "data").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="player-lifecycle-", dir=ROOT / "data") as temporary:
        folder = Path(temporary)
        source, executable = folder / "fixture.cpp", folder / "fixture.exe"
        source.write_text(harness)
        subprocess.run([compiler, "-std=c++20", "-O2", "-I" + str(ROOT / "src"),
                        str(source), "-o", str(executable)], check=True)
        result = subprocess.run([str(executable), str(folder / "fixture-data")],
                                check=True, capture_output=True, text=True)
        print(result.stdout, end="")
    report = {"passed": True, "game_launched": False, "storage_failure_modeled": True,
              "presence_scopes_reclaimed": 70000,
              "inputs": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in (ROOT / "src/channel_services.cpp", ROOT / "src/social_services.cpp",
                                      ROOT / "src/channel_store.cpp", Path(__file__))}}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
