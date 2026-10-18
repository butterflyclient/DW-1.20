"""Execute original Replay BFX materialization, projection, path and release.

First run --resource STOCK --output stock.json (the default stock path is local).
Then run --resource arena.bfx --geometry arena.geometry.json --report arena.report.json
--stock-baseline stock.json --output arena.native.json. No game calls or writes.
Native compatibility and source collision-audit readiness are separate fields.
"""

import argparse, collections, hashlib, json, sqlite3, struct, time, sys
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
ORIGINAL_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
STOCK_SHA = "e8738337750ba59eccb6c7a53cc35f7523ca47aa2a6b6152504f7322f6cbce91"


class Native:
    def __init__(self):
        raw = IMAGE.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA
        self.pe = pefile.PE(data=raw)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.vm = Uc(UC_ARCH_X86, UC_MODE_64)
        self.db = sqlite3.connect("file:" + str(IMAGE) + ".sqlite?mode=ro", uri=True)
        self.mapped = set()
        self.hooks = {}
        self.events = []
        self.tail = collections.deque(maxlen=25)
        self.seen = collections.Counter()
        self.boundary_calls = collections.Counter()
        self.heap = 0x60000000
        self.allocations = {}
        self.freed = set()
        self.stage = "init"
        self.started = time.monotonic()
        self.vm.hook_add(UC_HOOK_MEM_UNMAPPED, self.unmapped)
        self.vm.hook_add(UC_HOOK_CODE, self.code)
        self.stack = 0x70080008
        self.stop = 0x71000000
        self.map(self.stop)
        imports = {}
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for item in dll.imports:
                if item.name:
                    address = 0x72000000 + len(imports) * 16
                    self.put(item.address, struct.pack("<Q", address))
                    self.map(address)
                    name = item.name.decode()
                    imports[address] = name
                    self.hooks[address] = name
        self.imports = imports
        for name in [
            "bfx::InternalWarning",
            "j_memset",
            "__chkstk",
            "j___security_check_cookie",
        ]:
            row = self.db.execute(
                "select address from functions where name=?", (name,)
            ).fetchone()
            if row:
                self.hooks[int(row[0])] = name
        self.allocator = 0x50000000
        vtable = 0x50001000
        self.put(self.allocator, struct.pack("<Q", vtable))
        for slot, name in enumerate(
            ["allocate", "reallocate", "free", "allocator_tracking"]
        ):
            address = 0x73000000 + 16 * slot
            self.map(address)
            self.put(vtable + 8 * slot, struct.pack("<Q", address))
            self.hooks[address] = name

    def map(self, address):
        page = address & ~4095
        if page in self.mapped:
            return
        self.mapped.add(page)
        self.vm.mem_map(page, 4096)
        if self.base <= page < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage:
            data = self.pe.get_data(page - self.base, 4096)
            if data:
                self.vm.mem_write(page, data)

    def put(self, address, data):
        for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
            self.map(page)
        self.vm.mem_write(address, data)

    def get(self, address, fmt="<Q"):
        size = struct.calcsize(fmt)
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in self.mapped:
                if self.base <= page < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage:
                    self.map(page)
                else:
                    raise RuntimeError(("read outside known memory", hex(address), fmt))
        return struct.unpack(fmt, self.vm.mem_read(address, size))[0]

    def unmapped(self, uc, access, address, size, value, data):
        if (
            self.base <= address < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage
            or 0x70000000 <= address < 0x70100000
        ):
            for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                self.map(page)
            return True
        raise RuntimeError(
            (
                "unmapped",
                self.stage,
                hex(self.vm.reg_read(UC_X86_REG_RIP)),
                hex(address),
                size,
                list(self.tail),
            )
        )

    def ret(self, value=0):
        rsp = self.vm.reg_read(UC_X86_REG_RSP)
        self.vm.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        self.vm.reg_write(UC_X86_REG_RIP, self.get(rsp))
        self.vm.reg_write(UC_X86_REG_RSP, rsp + 8)

    def allocate(self, size):
        assert 0 <= size < 128 * 1024 * 1024, size
        size = max(size, 1)
        at = (self.heap + 31) & ~31
        self.heap = at + size
        assert self.heap < 0x6F000000
        self.put(at, bytes(size))
        self.allocations[at] = size
        return at

    def code(self, uc, address, size, data):
        self.tail.append(hex(address))
        self.seen[address] += 1
        if time.monotonic() - self.started > 1100:
            raise TimeoutError("bounded native gate time limit")
        name = self.hooks.get(address)
        if not name:
            return
        self.boundary_calls[name] += 1
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        r8 = uc.reg_read(UC_X86_REG_R8)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        if name == "allocate":
            self.ret(self.allocate(rdx))
        elif name == "free":
            if rdx:
                assert rdx in self.allocations and rdx not in self.freed, (
                    "invalid/double free",
                    hex(rdx),
                )
                self.freed.add(rdx)
                self.put(rdx, b"\xdd" * self.allocations[rdx])
            self.events.append(("free", hex(rdx)))
            self.ret()
        elif name == "allocator_tracking":
            self.ret(0)
        elif name == "reallocate":
            raise RuntimeError(
                ("unverified allocator realloc ABI", hex(rcx), hex(rdx), r8)
            )
        elif name == "j_memset":
            self.put(rcx, bytes([rdx & 255]) * r8)
            self.ret(rcx)
        elif name == "__chkstk":
            self.ret(uc.reg_read(UC_X86_REG_RAX))
        elif "security_check_cookie" in name:
            self.ret()
        elif name in [
            "InitializeCriticalSection",
            "DeleteCriticalSection",
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "InitializeCriticalSectionAndSpinCount",
            "InitializeCriticalSectionEx",
            "AcquireSRWLockExclusive",
            "ReleaseSRWLockExclusive",
        ]:
            self.ret(1)
        elif name in ["QueryPerformanceFrequency", "QueryPerformanceCounter"]:
            self.put(
                rcx,
                struct.pack(
                    "<Q",
                    (
                        1000000
                        if name.endswith("Frequency")
                        else int(time.monotonic() * 1e6)
                    ),
                ),
            )
            self.ret(1)
        elif name in ["GetCurrentThreadId", "GetCurrentProcessId"]:
            self.ret(1)
        elif name == "bfx::InternalWarning":
            text = bytearray()
            while len(text) < 1000:
                value = self.get(rcx + len(text), "<B")
                if not value:
                    break
                text.append(value)
            self.events.append(("native-warning", text.decode(errors="replace")))
            self.ret()
        else:
            raise RuntimeError(
                (
                    "unidentified external boundary",
                    self.stage,
                    name,
                    hex(address),
                    hex(rcx),
                    hex(rdx),
                    list(self.tail),
                )
            )

    def call(self, address, *args, stage=None):
        self.stage = stage or hex(address)
        self.put(self.stack, struct.pack("<Q", self.stop))
        for i, value in enumerate(args):
            if i < 4:
                self.vm.reg_write(
                    [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9][i],
                    value,
                )
            else:
                self.put(self.stack + 40 + 8 * (i - 4), struct.pack("<Q", value))
        self.vm.reg_write(UC_X86_REG_RSP, self.stack)
        self.vm.emu_start(address, self.stop, count=10000000)
        assert self.vm.reg_read(UC_X86_REG_RIP) == self.stop, (
            "instruction bound",
            self.stage,
            hex(self.vm.reg_read(UC_X86_REG_RIP)),
        )
        value = self.vm.reg_read(UC_X86_REG_RAX)
        print(self.stage, hex(value), flush=True)
        return value

    def verify_spawns(
        self, geometry, planner, layer, spec, pathflag, image, native_areas
    ):
        document = json.loads(geometry.read_bytes())
        spawns = document["spawns"]
        assert 1 <= len(spawns) <= 256
        project = int(
            self.db.execute(
                "select address from functions where name=?",
                ("bfx::AreaFlags::EndianSwap",),
            ).fetchone()[0]
        )
        queries = []
        for i, spawn in enumerate(spawns):
            point = 0x51000000 + i * 128
            out = point + 32
            self.put(point, struct.pack("<3f", *spawn))
            self.put(out, bytes(16))
            area = self.call(
                0x141FE4F70, planner, point, 0, spec, stage="SpawnClosest" + str(i)
            )
            assert area in native_areas, ("invalid spawn area", i)
            self.call(project, out, area, point, 0, stage="SpawnProject" + str(i))
            projected = list(struct.unpack("<3f", self.vm.mem_read(out, 12)))
            queries.append(
                dict(
                    index=i,
                    spawn=spawn,
                    projected=projected,
                    area_offset=area - image,
                    area=area,
                    address=out,
                )
            )
        routes = []
        for i, goal in enumerate(queries[1:], 1):
            start = queries[0]
            queue = collections.deque([start["area"]])
            visited = {start["area"]}
            while queue:
                current = queue.popleft()
                for edge in range(self.get(current + 56, "<I") & 127):
                    neighbor = self.get(current + 72 + 32 * edge)
                    if neighbor and neighbor not in visited:
                        assert neighbor in native_areas
                        visited.add(neighbor)
                        queue.append(neighbor)
            expected = goal["area"] in visited
            route = self.call(
                0x141FC6F90,
                layer,
                start["address"],
                start["area"],
                goal["address"],
                goal["area"],
                spec,
                pathflag,
                stage="SpawnRoute" + str(i),
            )
            assert bool(route) == expected, ("Native/BFS route disagreement", i)
            count = self.get(route + 16, "<I") if route else 0
            if route:
                sequence = [self.get(self.get(route + 8) + 8 * j) for j in range(count)]
                assert sequence[0] == start["area"] and sequence[-1] == goal["area"]
                for a, b in zip(sequence, sequence[1:]):
                    assert any(
                        self.get(a + 72 + 32 * j) == b
                        for j in range(self.get(a + 56, "<I") & 127)
                    )
                self.call(
                    self.get(self.get(route)),
                    route,
                    1,
                    stage="DestroySpawnRoute" + str(i),
                )
            routes.append(
                dict(
                    start=0,
                    goal=i,
                    cpu_portal_connected=expected,
                    native_path_found=bool(route),
                    path_area_count=count,
                )
            )
        return dict(
            queries=queries,
            routes=routes,
            all_spawns_connected=all(row["cpu_portal_connected"] for row in routes),
        )

    def run(self, resource, geometry=None):
        data = resource.read_bytes()
        build_scale = struct.unpack("<f", self.pe.get_data(0x23CBCEC, 4))[0]
        assert build_scale == 72.0
        params = 0x50002000
        self.put(params, struct.pack("<fII", build_scale, 2, 0))
        system = self.call(
            0x141FAC5C0, 0, 0, params, self.allocator, stage="SystemCreate"
        )
        assert system == self.get(0x152D5B470)
        self.call(0x141FCA0E0, system, stage="RegisterPlannerSystem")
        self.call(0x141FB4AD0, system, stage="SystemInstanceStart")
        handle = 0x50003000
        self.put(handle, bytes(24))
        self.call(0x141FA8320, handle, system, stage="CreateSpace")
        space = self.get(self.get(handle))
        image = self.allocate(len(data))
        self.put(image, data)
        config = 0x50004000
        self.put(
            config,
            struct.pack("<3f", 0, 0, 0)
            + self.pe.get_data(0x5A4C840, 16)
            + struct.pack("<I", 0),
        )
        manager = self.get(system + 144)
        result = self.call(
            0x141FA9900, manager, space, image, config, stage="AddResourceImage"
        )
        assert result
        planner = self.get(self.get(space + 208) + 8)
        layer = self.get(planner + 32)
        assert layer
        spec = 0x50005000
        specbytes = bytearray(80)
        struct.pack_into("<5I", specbytes, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        specbytes[72] = 1
        self.put(spec, bytes(specbytes))
        area_at = 48 + 340
        area_end = area_at + struct.unpack_from("<I", data, 56)[0]
        pair = None
        while area_at < area_end and pair is None:
            edges = struct.unpack_from("<I", data, area_at + 56)[0] & 127
            for i in range(edges):
                neighbor = struct.unpack_from("<Q", data, area_at + 72 + 32 * i)[0]
                if neighbor:
                    pair = (area_at, 48 + neighbor)
                    break
            area_at += 72 + 32 * edges
        assert pair, "No stock connected portal"
        # Use a distant polygon in the same authored portal component rather
        # than only an adjacent pair, so the stock control exercises search.
        raw_neighbors = {}
        at = 48 + 340
        while at < area_end:
            count = struct.unpack_from("<I", data, at + 56)[0] & 127
            raw_neighbors[at] = [
                48 + neighbor
                for i in range(count)
                if (neighbor := struct.unpack_from("<Q", data, at + 72 + 32 * i)[0])
            ]
            at += 72 + 32 * count
        queue = collections.deque([pair[0]])
        distance = {pair[0]: 0}
        while queue:
            current = queue.popleft()
            for neighbor in raw_neighbors[current]:
                assert neighbor in raw_neighbors
                if neighbor not in distance:
                    distance[neighbor] = distance[current] + 1
                    queue.append(neighbor)
        pair = (pair[0], max(distance, key=distance.get))
        nearest = []
        points = []
        for i, offset in enumerate(pair):
            point = data[offset + 32 : offset + 44]
            at = 0x50006000 + i * 4096
            self.put(at, point)
            points.append(at)
            nearest.append(
                self.call(
                    0x141FE4F70, planner, at, 0, spec, stage="GetClosestArea" + str(i)
                )
            )
        assert all(nearest) and nearest[0] != nearest[1], nearest
        pathflag = 0x50008000
        self.put(pathflag, b"\0")
        path = self.call(
            0x141FC6F90,
            layer,
            points[0],
            nearest[0],
            points[1],
            nearest[1],
            spec,
            pathflag,
            stage="FindPath",
        )
        assert path, "Native FindPath returned null"
        path_count = self.get(path + 16, "<I")
        assert 2 <= path_count < 100000
        underlying = [
            self.call(0x141FF5180, path, i, stage="PathArea" + str(i))
            for i in range(path_count)
        ]
        assert underlying[0] == nearest[0] and underlying[-1] == nearest[1], (
            "path endpoints",
            underlying,
            nearest,
        )
        native_area_offsets = set()
        at = 48 + 340
        while at < area_end:
            native_area_offsets.add(image + at)
            at += 72 + 32 * (struct.unpack_from("<I", data, at + 56)[0] & 127)
        assert all(
            area in native_area_offsets for area in underlying
        ), "Path points outside loaded graph"
        for a, b in zip(underlying, underlying[1:]):
            count = self.get(a + 56, "<I") & 127
            assert any(
                self.get(a + 72 + 32 * i) == b for i in range(count)
            ), "Native path uses nonexistent portal"
        self.call(self.get(self.get(path)), path, 1, stage="DestroyPath")
        spawn_proof = (
            self.verify_spawns(
                geometry, planner, layer, spec, pathflag, image, native_area_offsets
            )
            if geometry
            else None
        )
        duplicate = self.call(
            0x141FA9900, manager, space, image, config, stage="RejectDuplicateResource"
        )
        assert duplicate == 0 and self.get(manager + 32, "<I") == 1
        self.call(0x141FAA130, handle, image, stage="RemoveResource")
        assert self.get(manager + 32, "<I") == 0, "Resource registry did not retire"
        after = self.call(
            0x141FE4F70, planner, points[0], 0, spec, stage="ClosestAfterRemoval"
        )
        assert after == 0
        reused = self.call(
            0x141FA9900, manager, space, image, config, stage="RejectUsedImage"
        )
        assert reused == 0 and self.get(manager + 32, "<I") == 0
        fresh = self.allocate(len(data))
        self.put(fresh, data)
        reloaded = self.call(
            0x141FA9900, manager, space, fresh, config, stage="ReloadFreshImage"
        )
        assert reloaded and self.get(manager + 32, "<I") == 1
        fresh_area = self.call(
            0x141FE4F70, planner, points[0], 0, spec, stage="ClosestAfterReload"
        )
        assert fresh_area in {fresh + offset - image for offset in native_area_offsets}
        self.call(0x141FAA130, handle, fresh, stage="RemoveReloadedImage")
        assert self.get(manager + 32, "<I") == 0

        return dict(
            system=hex(system),
            space=hex(space),
            resource=hex(result),
            nearest_areas=[hex(a) for a in nearest],
            path=hex(path),
            path_area_count=path_count,
            control_cpu_component_areas=len(distance),
            control_cpu_minimum_portal_hops=distance[pair[1]],
            path_area_offsets=[area - image for area in underlying],
            native_path_endpoints_verified=True,
            native_portal_chain_verified=True,
            native_resource_removed=True,
            native_duplicate_and_used_image_rejected=True,
            native_fresh_image_reload_verified=True,
            spawn_proof=spawn_proof,
            events=self.events,
            allocations=len(self.allocations),
            original_instruction_addresses_executed=len(
                [
                    a
                    for a in self.seen
                    if self.base <= a < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage
                ]
            ),
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--resource",
        type=Path,
        default=Path(r"E:\mw124-conversion-builds\_stock_ship_nav\shipment_graph.bin"),
    )
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--geometry", type=Path)
    p.add_argument("--audit", "--report", dest="audit", type=Path)
    p.add_argument("--stock-baseline", type=Path)
    args = p.parse_args()
    tool_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    resource_sha = hashlib.sha256(args.resource.read_bytes()).hexdigest()
    baseline_sha = None
    if resource_sha != STOCK_SHA:
        assert (
            args.stock_baseline
        ), "Run the stock Shipment control first and supply --stock-baseline"
        baseline_raw = args.stock_baseline.read_bytes()
        baseline = json.loads(baseline_raw)
        assert baseline["passed"] and baseline["resource_sha256"] == STOCK_SHA
        assert (
            baseline["tool_sha256"] == tool_sha
            and baseline["original_image_sha256"] == ORIGINAL_SHA
        )
        baseline_sha = hashlib.sha256(baseline_raw).hexdigest()
    audit = None
    if args.audit:
        audit = json.loads(args.audit.read_bytes())
        assert (
            hashlib.sha256(args.resource.read_bytes()).hexdigest()
            == audit["resource_sha256"]
        )
        assert (
            args.geometry and args.geometry.resolve() == Path(audit["input"]).resolve()
        )
        assert (
            hashlib.sha256(args.geometry.read_bytes()).hexdigest()
            == audit["input_sha256"]
        )
    native = Native()
    try:
        result = native.run(args.resource, args.geometry)
        result["completed"] = True
    except Exception as exc:
        result = dict(
            completed=False,
            error=str(exc),
            stage=native.stage,
            tail=list(native.tail),
            events=native.events,
        )
    pins = []
    for address in [
        0x1410EAC50,
        0x141FAC5C0,
        0x141FAC600,
        0x141FCA0E0,
        0x141FB4AD0,
        0x141FA8320,
        0x141FA9900,
        0x141FDD0F0,
        0x141FE4F70,
        0x141FC6F90,
        0x141FF5180,
        0x141FAA130,
    ]:
        name, size = native.db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        pins.append(
            dict(
                name=name,
                address=hex(address),
                bytes=size,
                sha256=hashlib.sha256(
                    native.pe.get_data(address - native.base, size)
                ).hexdigest(),
            )
        )
    geometry_document = (
        None if args.geometry is None else json.loads(args.geometry.read_bytes())
    )
    collision_certified = bool(
        audit
        and geometry_document
        and geometry_document.get("collision_complete") is True
        and geometry_document.get("provenance", {}).get("collision_complete") is True
        and not geometry_document.get("provenance", {}).get("synthetic", False)
        and audit.get("geometry_provenance", {}).get("collision_complete") is True
        and not audit.get("geometry_provenance", {}).get("synthetic", False)
        and audit.get("collision_fidelity", {}).get("sampled_checks_passed") is True
    )
    passed = bool(
        result["completed"]
        and (
            result.get("spawn_proof") is None
            or result["spawn_proof"]["all_spawns_connected"]
        )
    )
    result.update(
        passed=passed,
        tool_sha256=tool_sha,
        stock_baseline_sha256=baseline_sha,
        native_entry_pins=pins,
        modeled_boundaries=dict(native.boundary_calls),
        geometry_sha256=(
            None
            if args.geometry is None
            else hashlib.sha256(args.geometry.read_bytes()).hexdigest()
        ),
        resource_audit_sha256=(
            None
            if args.audit is None
            else hashlib.sha256(args.audit.read_bytes()).hexdigest()
        ),
        collision_geometry_certified=collision_certified,
        collision_certification_scope="Current hash-matched source geometry and resource audit; native consumer testing does not certify missing collision coverage",
        resource_collision_complete=(
            None
            if audit is None
            else audit.get("geometry_provenance", {}).get("collision_complete", False)
        ),
        original_runtime_params=dict(
            scale=struct.unpack("<f", native.pe.get_data(0x23CBCEC, 4))[0],
            up_axis=2,
            memory_tracking=False,
            source="Nav_InitNavPower0x1410EAC50",
        ),
        original_image_sha256=ORIGINAL_SHA,
        resource_path=str(args.resource),
        resource_sha256=resource_sha,
        game_execution=False,
        nav_semantics_modeled=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: value
                for key, value in result.items()
                if key not in ("events", "native_entry_pins", "modeled_boundaries")
            },
            indent=2,
        )
    )
    if not result["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
