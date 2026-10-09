#!/usr/bin/env python3
"""Measure only the real public setup or synthetic Rust creation runner on Linux.

No witness inputs, key-content reads, shell commands, downloads or group kills.
The in-scope copy stays alive until it has harvested the cgroup counters.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import stat
import subprocess
import sys
import time
import uuid

GIB = 1024 ** 3
UNMEASURED = "UNMEASURED"
TASKS_MAX = 512
OUTPUT_LIMIT = 65536
CGROUP_ROOT = Path("/sys/fs/cgroup")
SCALAR_R = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
# Conservative trial policy, NOT a measured whole-prover minimum. The recorded
# 5,611,078,880-byte recursion-array component excludes shrink/FFT/decoded PK.
WRAPPED_SAFETY_FLOOR = 8 * GIB
UNVERIFIED_FIELDS = ("source_qualification", "setup_qualification", "program_identity",
                     "root_eligibility", "global_unspentness", "asset_backing", "finality",
                     "deployment_profile_qualification")
COUNTER_FILES = ("memory.current", "memory.peak", "memory.events", "memory.stat",
                 "memory.swap.current", "pids.events")
SETUP_FILES = {"groth16_circuit.bin": 2437991441, "groth16_pk.bin": 5862173061,
               "groth16_vk.bin": 492, ".complete": 0}
VK_SHA256 = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
MAX_BINDING_BYTES = 4096
MAX_CAPSULE_BYTES = (len(b"ziquid.samechain.release.v1") + 24 + 4 + 16
                     + len(b"Z2Z_SAMECHAIN_RELEASE_CAPSULE\0") + 2 + 4 + 4096 + 4 + 1024 + 4 + 356)


class BenchmarkError(Exception):
    """Sanitized category; never include supplied paths or process diagnostics."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise SystemExit("invalid owner benchmark arguments; use --help")


def byte_size(value):
    match = re.fullmatch(r"([1-9][0-9]*)(B|KiB|MiB|GiB)?", value)
    if not match:
        raise argparse.ArgumentTypeError("positive integer bytes or KiB/MiB/GiB required")
    result = int(match[1]) * {None: 1, "B": 1, "KiB": 1024,
                             "MiB": 1024 ** 2, "GiB": GIB}[match[2]]
    if result > (1 << 63) - 1:
        raise argparse.ArgumentTypeError("memory size exceeds supported range")
    return result


def public_pin(value):
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value) or int(value[2:], 16) == 0:
        raise argparse.ArgumentTypeError("nonzero fixed-width public hex pin required")
    return value.lower()


def program_pin(value):
    value = public_pin(value)
    if int(value[2:], 16) >= SCALAR_R:
        raise argparse.ArgumentTypeError("canonical owner program scalar required")
    return value


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise argparse.ArgumentTypeError("absolute path without parent traversal required")
    return path


def seconds(value):
    if not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= 86400:
        raise argparse.ArgumentTypeError("timeout must be 1..86400 seconds")
    return int(value)


def parse_args(argv=None):
    parser = ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=("setup", "wrapped"), required=True)
    for flag in ("binary", "example", "elf", "groth16-artifact-base", "private-temp-dir"):
        parser.add_argument("--" + flag, type=absolute_path, required=True)
    parser.add_argument("--elf-sha256", type=public_pin, required=True)
    parser.add_argument("--program-vkey", type=program_pin, required=True)
    parser.add_argument("--timeout-seconds", type=seconds, required=True)
    parser.add_argument("--memory-max", type=byte_size, required=True)
    parser.add_argument("--reserve-memory", type=byte_size, required=True,
                        help="explicit local headroom, at least 1GiB; not charged to scope")
    parser.add_argument("--release-dir", type=absolute_path)
    parser.add_argument("--backup-key-file", type=absolute_path)
    parser.add_argument("--op-id", type=public_pin)
    args = parser.parse_args(argv)
    capsule_args = (args.release_dir, args.backup_key_file, args.op_id)
    if args.mode == "wrapped" and any(value is None for value in capsule_args):
        parser.error("wrapped mode requires release directory, key file and operation id")
    if args.mode == "setup" and any(value is not None for value in capsule_args):
        parser.error("setup mode does not accept capsule arguments")
    return args


def parse_meminfo(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"):
            key = fields[0][:-1]
            if key in result or len(fields) != 3 or fields[2] != "kB" or not fields[1].isdigit():
                raise BenchmarkError("invalid memory envelope counters")
            result[key] = int(fields[1]) * 1024
    return result


def check_envelope(mode, cap, reserve, available):
    if reserve < GIB:
        return "local reserve must be at least 1GiB (harness safety policy)"
    if not isinstance(available, int) or available < 0:
        return "MemAvailable is UNMEASURED"
    if cap <= 0 or cap + reserve > available:
        return "memory cap plus local reserve exceeds current available headroom"
    if mode == "wrapped" and cap <= WRAPPED_SAFETY_FLOOR:
        return "wrapped cap must exceed conservative 8GiB safety floor; not a measured minimum"
    return None


def parse_counters(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in result or not re.fullmatch(r"[0-9]+", fields[1]):
            raise BenchmarkError("invalid cgroup counters")
        result[fields[0]] = int(fields[1])
    return result


def normalize_accounting(counters, sampled_current=0, rss_peak=None):
    errors = []

    def number(name):
        raw = counters.get(name, "").strip()
        if not re.fullmatch(r"[0-9]+", raw):
            errors.append(name + " missing or invalid")
            return UNMEASURED
        return int(raw)

    def fields(name, required):
        try:
            value = parse_counters(counters.get(name, ""))
        except BenchmarkError:
            value = {}
        if not set(required).issubset(value):
            errors.append(name + " missing or invalid")
        return value

    current, peak = number("memory.current"), number("memory.peak")
    swap = number("memory.swap.current")
    usage = fields("memory.stat", ("anon", "file", "shmem"))
    events = fields("memory.events", ("max", "oom", "oom_kill"))
    tasks = fields("pids.events", ("max",))
    if isinstance(peak, int):
        observed = [sampled_current]
        if isinstance(current, int):
            observed.append(current)
        if peak < max(observed):
            errors.append("memory.peak inconsistent with current samples")
        if usage.get("anon", 0) + usage.get("file", 0) > peak:
            errors.append("memory.stat exceeds memory.peak")
    if usage.get("shmem", 0) > usage.get("file", 0):
        errors.append("shmem is not a subset of file")
    if isinstance(swap, int) and swap != 0:
        errors.append("scope unexpectedly used swap")
    return {"status": UNMEASURED if errors else "MEASURED", "errors": errors,
            "whole_scope_peak_bytes": UNMEASURED if errors else peak,
            "reported_scope_peak_bytes": peak,
            "current_bytes_at_harvest": current,
            "sampled_current_max_bytes": sampled_current,
            "anon_bytes_at_harvest": usage.get("anon", UNMEASURED),
            "file_including_shmem_bytes": usage.get("file", UNMEASURED),
            "shmem_subset_bytes": usage.get("shmem", UNMEASURED),
            "swap_bytes_at_harvest": swap, "memory_events": events or UNMEASURED,
            "pids_events": tasks or UNMEASURED,
            "rss_max_bytes": rss_peak if isinstance(rss_peak, int) else UNMEASURED,
            "rss_method": "Linux wait4 ru_maxrss, largest reaped process RSS; not tree sum",
            "accounting_method": "cgroup v2 charged scope memory, including keeper and descendants; shmem already in file/total; not total resident tree, preexisting shared pages may be charged elsewhere"}


def limit_status(counters):
    try:
        memory = parse_counters(counters.get("memory.events", ""))
        tasks = parse_counters(counters.get("pids.events", ""))
    except BenchmarkError:
        return UNMEASURED
    if memory.get("oom", 0) or memory.get("oom_kill", 0):
        return "OOM_LIMIT"
    if tasks.get("max", 0):
        return "TASK_LIMIT"
    if memory.get("max", 0):
        return "MEMORY_LIMIT"
    if not {"max", "oom", "oom_kill"}.issubset(memory) or "max" not in tasks:
        return UNMEASURED
    return "NO_LIMIT_OBSERVED"


def outcome_status(mode, returncode, valid_output, limit, ambiguous):
    if ambiguous:
        return "AMBIGUOUS_FAILURE"
    if limit not in ("NO_LIMIT_OBSERVED", UNMEASURED):
        return limit
    if returncode != 0 or not valid_output:
        return "RUNNER_FAILURE"
    if limit == UNMEASURED:
        return "BENCHMARK_UNMEASURED"
    return "PUBLIC_SETUP_ONLY" if mode == "setup" else "ACTUAL_WRAPPED_CAPSULE"


def validate_private_root(path):
    path = absolute_path(str(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open("/", flags)
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid not in (0, os.geteuid()) or (mode & 0o022 and not
                                                       (info.st_uid == 0 and mode == 0o1777)):
                raise BenchmarkError("private root ancestor policy rejected")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise BenchmarkError("private root must be caller-owned mode0700")
    except OSError:
        raise BenchmarkError("private root unavailable or symlink rejected") from None
    finally:
        os.close(fd)

def private_file(path, max_bytes, exact_bytes=None):
    """Descriptor-relative trusted custody read capability; no content read here."""
    path = absolute_path(str(path))
    validate_private_root(path.parent)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in (None, *path.parent.parts[1:]):
            if part is not None:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=directory)
                os.close(directory)
                directory = next_fd
            info = os.fstat(directory)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid not in (0, os.geteuid()) or (mode & 0o022 and not
                                                       (info.st_uid == 0 and mode == 0o1777)):
                raise BenchmarkError("private custody ancestor rejected")
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise BenchmarkError("private custody directory rejected")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > max_bytes
                    or (exact_bytes is not None and info.st_size != exact_bytes)):
                raise BenchmarkError("private custody file rejected")
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError:
        raise BenchmarkError("private custody file unavailable") from None
    finally:
        os.close(directory)


def validate_backup_key(path):
    fd = private_file(path, 32, exact_bytes=32)
    os.close(fd)  # Never read, copy or hash owner key contents in this Python process.


def capsule_identity(path):
    fd = private_file(path, MAX_CAPSULE_BYTES)
    try:
        with os.fdopen(fd, "rb") as file:
            before = os.fstat(file.fileno())
            raw = file.read(MAX_CAPSULE_BYTES + 1)
            after = os.fstat(file.fileno())
            if len(raw) > MAX_CAPSULE_BYTES or len(raw) != before.st_size or (
                    before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise BenchmarkError("encrypted capsule changed or exceeded bound")
            return "0x" + hashlib.sha256(raw).hexdigest()
    except OSError:
        raise BenchmarkError("encrypted capsule unavailable") from None


def file_identity(path, executable=False, max_bytes=512 * 1024 * 1024):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            before = os.fstat(file.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise BenchmarkError("selected public file is not bounded and regular")
            if executable and (not before.st_mode & 0o111 or file.read(4) != b"\x7fELF"):
                raise BenchmarkError("selected runner must be an executable native ELF")
            file.seek(0)
            digest = hashlib.file_digest(file, "sha256").hexdigest()
            after = os.fstat(file.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise BenchmarkError("selected public file changed during inventory")
            return {"sha256": "0x" + digest, "bytes": after.st_size}
    except OSError:
        raise BenchmarkError("selected public file unavailable") from None


def validate_inputs(args):
    if args.binary.name != "ziquid" or args.example.name != "owner_creation_qualification":
        raise BenchmarkError("only ziquid and owner_creation_qualification executables accepted")
    validate_private_root(args.private_temp_dir)
    if args.mode == "wrapped":
        validate_private_root(args.release_dir)
        validate_backup_key(args.backup_key_file)
    identities = {"binary": file_identity(args.binary, executable=True),
                  "example": file_identity(args.example, executable=True),
                  "elf": file_identity(args.elf, max_bytes=16 * 1024 * 1024)}
    if identities["elf"]["sha256"] != args.elf_sha256:
        raise BenchmarkError("owner ELF hash mismatch before launch")
    if args.groth16_artifact_base.name == "v6.1.0":
        raise BenchmarkError("select setup base, not v6.1.0 child")
    directory = args.groth16_artifact_base / "v6.1.0"
    try:
        if not directory.is_dir():
            raise BenchmarkError("local public setup unavailable; no download allowed")
        for name, size in SETUP_FILES.items():
            info = (directory / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                raise BenchmarkError("local public setup incomplete; no download allowed")
    except OSError:
        raise BenchmarkError("local public setup unavailable; no download allowed") from None
    vk = file_identity(directory / "groth16_vk.bin", max_bytes=492)
    if vk["sha256"] != "0x" + VK_SHA256:
        raise BenchmarkError("local setup VK does not match frozen verifier")
    identities["setup"] = {"artifact_bytes": sum(SETUP_FILES.values()), "vk": vk,
                           "pk_circuit_sha256": UNMEASURED,
                           "qualification": "UNVERIFIED; wrapped Rust runner checks exact artifact bytes"}
    return identities


def runner_command(args):
    if args.mode == "setup":
        return [str(args.binary), "samechain", "owner-program", "--elf", str(args.elf),
                "--elf-sha256", args.elf_sha256]
    return [str(args.example), "--binary", str(args.binary), "--elf", str(args.elf),
            "--elf-sha256", args.elf_sha256, "--program-vkey", args.program_vkey,
            "--private-temp-dir", str(args.private_temp_dir), "--groth16-artifact-base",
            str(args.groth16_artifact_base), "--timeout-seconds", str(args.timeout_seconds),
            "--release-dir", str(args.release_dir), "--backup-key-file", str(args.backup_key_file),
            "--op-id", args.op_id]


def scope_command(args, unit):
    argv = ["--mode", args.mode, "--binary", str(args.binary), "--example", str(args.example),
            "--elf", str(args.elf), "--elf-sha256", args.elf_sha256,
            "--program-vkey", args.program_vkey, "--groth16-artifact-base",
            str(args.groth16_artifact_base), "--private-temp-dir", str(args.private_temp_dir),
            "--timeout-seconds", str(args.timeout_seconds), "--memory-max", str(args.memory_max),
            "--reserve-memory", str(args.reserve_memory)]
    if args.mode == "wrapped":
        argv += ["--release-dir", str(args.release_dir), "--backup-key-file", str(args.backup_key_file),
                 "--op-id", args.op_id]
    return ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--no-ask-password",
            "--expand-environment=no", "--description=Controlled owner proof benchmark",
            "--slice=app.slice", "--unit=" + unit, "--property=MemoryAccounting=yes",
            "--property=MemoryMax=" + str(args.memory_max), "--property=MemorySwapMax=0",
            "--property=TasksAccounting=yes", "--property=TasksMax=" + str(TASKS_MAX),
            "--property=OOMPolicy=continue", "--property=Delegate=no",
            "--", sys.executable, "-I", str(Path(__file__).resolve()), *argv]


def strict_json(raw):
    def invalid_number(_):
        raise BenchmarkError("invalid JSON number")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise BenchmarkError("duplicate public JSON field")
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_number)
    except (ValueError, UnicodeError):
        raise BenchmarkError("runner public JSON rejected") from None


def binding_frame(text, args, deployment):
    if not isinstance(text, str) or len(text) > 2 + 2 * MAX_BINDING_BYTES or not re.fullmatch(
            r"0x(?:[0-9a-f]{2})+", text):
        raise BenchmarkError("runner release binding framing rejected")
    frame = bytes.fromhex(text[2:])
    at = 0

    def take(count):
        nonlocal at
        if count > len(frame) - at:
            raise BenchmarkError("runner release binding truncated")
        result = frame[at:at + count]
        at += count
        return result

    if take(len(b"Z2Z_SAMECHAIN_RELEASE_BINDING\0")) != b"Z2Z_SAMECHAIN_RELEASE_BINDING\0" or take(2) != b"\0\1":
        raise BenchmarkError("runner release binding schema rejected")
    if take(32).hex() != args.op_id[2:]:
        raise BenchmarkError("runner release binding operation mismatch")
    deployment_length = int.from_bytes(take(4), "big")
    encoded = take(deployment_length)
    if not isinstance(deployment, dict) or set(deployment) != {"chain_id", "authority", "authority_code",
            "verifier", "verifier_code", "owner_program", "schema"}:
        raise BenchmarkError("runner release binding deployment rejected")
    if (not isinstance(deployment["chain_id"], str) or not re.fullmatch(r"[1-9][0-9]*", deployment["chain_id"])
            or not 0 < int(deployment["chain_id"]) < 1 << 64 or type(deployment["schema"]) is not int
            or deployment["schema"] != 1 or deployment["owner_program"] != args.program_vkey):
        raise BenchmarkError("runner release binding deployment rejected")
    expected = b"Z2Z_SAMECHAIN_DEPLOYMENT\0\0\1" + int(deployment["chain_id"]).to_bytes(8, "big")
    for field, size in (("authority", 20), ("authority_code", 32), ("verifier", 20),
                        ("verifier_code", 32), ("owner_program", 32)):
        value = deployment[field]
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]{" + str(size * 2) + "}", value):
            raise BenchmarkError("runner release binding deployment framing rejected")
        decoded = bytes.fromhex(value[2:])
        if not any(decoded):
            raise BenchmarkError("runner release binding zero deployment pin")
        expected += decoded
    expected += b"\0\1"
    if encoded != expected or take(1) != b"\4" or take(1) not in (b"\0", b"\1"):
        raise BenchmarkError("runner release binding operation/deployment mismatch")
    packet_digest, program, journal_digest = take(32), take(32), take(32)
    if not any(packet_digest) or program.hex() != args.program_vkey[2:] or not any(journal_digest):
        raise BenchmarkError("runner release binding public pins rejected")
    if int.from_bytes(take(8), "big") == 0 or take(1) != b"\0" or at != len(frame):
        raise BenchmarkError("runner release binding expiry/cardinality/exhaustion rejected")
    # The Rust runner independently derives packet/journal expectations. Python
    # validates their canonical envelope/pins, not secret relation or target admission.
    return frame

def validate_output(raw, args):
    if len(raw) > OUTPUT_LIMIT:
        raise BenchmarkError("runner output exceeded bound")
    value = strict_json(raw)
    if not isinstance(value, dict):
        raise BenchmarkError("runner public JSON must be an object")
    common = {"kind", "elf_sha256", "program_vkey", "proof_certificate",
              "financial_execution", "strict_matching_privacy", *UNVERIFIED_FIELDS}
    if value.get("elf_sha256") != args.elf_sha256 or value.get("program_vkey") != args.program_vkey:
        raise BenchmarkError("runner public pins mismatch")
    if any(value.get(name) != "UNVERIFIED" for name in UNVERIFIED_FIELDS) or any(
            value.get(name) is not False for name in ("financial_execution", "strict_matching_privacy")):
        raise BenchmarkError("runner misrepresented unqualified financial or privacy evidence")
    if args.mode == "setup":
        if set(value) != common | {"evidence"} or value.get("kind") != "samechain_owner_program" or (
                value.get("evidence") != "actual_local_light_program_setup" or
                value.get("proof_certificate") is not False):
            raise BenchmarkError("actual public setup output mismatch")
        return value
    extra = {"status", "operation", "fixture", "expected_deployment", "op_id", "binding",
             "binding_digest", "release_digest", "capsule", "witness_bytes", "packet_bytes",
             "elapsed_ms", "sdk_storage_boundary"}
    if set(value) != common | extra or value.get("kind") != "samechain_owner_creation_qualification" or (
            value.get("status") != "ACTUAL_WRAPPED_CAPSULE" or value.get("operation") != "creation" or
            value.get("fixture") != "GENERATED_TEST_DEPLOYMENT_NOT_BACKED_TARGET" or
            value.get("proof_certificate") is not False or
            value.get("sdk_storage_boundary") != "UNQUALIFIED_EXTERNAL_DEV_SHM_RAII_RETENTION"):
        raise BenchmarkError("actual Rust wrapped capsule output mismatch")
    for name in ("witness_bytes", "packet_bytes", "elapsed_ms"):
        if type(value[name]) is not int or value[name] < (0 if name == "elapsed_ms" else 1):
            raise BenchmarkError("runner public byte counts rejected")
    if value["op_id"] != args.op_id or value["capsule"] != args.op_id[2:] + ".release":
        raise BenchmarkError("runner capsule operation identity mismatch")
    binding = binding_frame(value["binding"], args, value["expected_deployment"])
    if value["binding_digest"] != "0x" + hashlib.sha256(binding).hexdigest():
        raise BenchmarkError("runner canonical binding digest mismatch")
    if value["release_digest"] != capsule_identity(args.release_dir / value["capsule"]):
        raise BenchmarkError("runner encrypted capsule digest mismatch")
    return value


def snapshot(group):
    value = {}
    for name in COUNTER_FILES:
        try:
            value[name] = (group / name).read_text(encoding="ascii")
        except (OSError, UnicodeError):
            pass  # Missing counters are UNMEASURED, never zero.
    return value


def verify_scope(args, unit):
    membership = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"z2z-owner-bench-[0-9a-f]{32}\.scope", unit) or not membership.startswith("0::/"):
        raise BenchmarkError("unified transient scope placement unavailable")
    relative = Path(membership[4:])
    if ".." in relative.parts or relative.name != unit or "user@" + str(os.geteuid()) + ".service" not in relative.parts:
        raise BenchmarkError("benchmark is not in its selected user scope")
    group = CGROUP_ROOT / relative
    controllers = (group.parent / "cgroup.controllers").read_text(encoding="ascii").split()
    if not {"memory", "pids"}.issubset(controllers):
        raise BenchmarkError("memory and task controllers unavailable")
    for name, expected in (("memory.max", args.memory_max), ("memory.swap.max", 0), ("pids.max", TASKS_MAX)):
        if (group / name).read_text(encoding="ascii").strip() != str(expected):
            raise BenchmarkError("scope resource cap not enforced")
    available = parse_meminfo(Path("/proc/meminfo").read_text(encoding="ascii")).get("MemAvailable")
    ancestor = group.parent
    while ancestor != CGROUP_ROOT:
        maximum = (ancestor / "memory.max").read_text(encoding="ascii").strip()
        if maximum != "max":
            current = (ancestor / "memory.current").read_text(encoding="ascii").strip()
            if not maximum.isdigit() or not current.isdigit():
                raise BenchmarkError("ancestor memory headroom unavailable")
            available = min(available, int(maximum) - int(current)) if available is not None else None
        ancestor = ancestor.parent
    reason = check_envelope(args.mode, args.memory_max, args.reserve_memory, available)
    if reason:
        raise BenchmarkError(reason)
    return group, controllers


def measure(args, unit):
    group, controllers = verify_scope(args, unit)
    identities = validate_inputs(args)
    envelope = parse_meminfo(Path("/proc/meminfo").read_text(encoding="ascii"))
    # Inventory may take time; recheck fresh headroom immediately before launch.
    verify_scope(args, unit)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {key: os.environ[key] for key in ("HOME", "PATH") if key in os.environ}
    environment.update(SP1_PROVER="cpu", SP1_CIRCUIT_MODE="release",
                       SP1_GROTH16_CIRCUIT_PATH=str(args.groth16_artifact_base), TMPDIR=str(args.private_temp_dir))
    started = time.monotonic()
    child = subprocess.Popen(runner_command(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=environment, close_fds=True)
    os.set_blocking(child.stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    output = bytearray()
    sampled, samples, losses, shmem_max, file_max = 0, 0, 0, 0, 0
    placement_seen, ambiguous, eof, overflow = False, False, False, False
    status, usage = None, None
    # Rust's T setup + 2T proof/cleanup +60s watchdog are primary in wrapped mode.
    deadline = started + (args.timeout_seconds if args.mode == "setup" else 3 * args.timeout_seconds + 120)
    while True:
        counters = snapshot(group)
        samples += 1
        try:
            current = counters.get("memory.current", "").strip()
            if not current.isdigit():
                raise BenchmarkError("current counter unavailable")
            sampled = max(sampled, int(current))
            fields = parse_counters(counters.get("memory.stat", ""))
            if not {"file", "shmem"}.issubset(fields):
                raise BenchmarkError("shared accounting unavailable")
            shmem_max, file_max = max(shmem_max, fields["shmem"]), max(file_max, fields["file"])
        except BenchmarkError:
            losses += 1
        if status is None:
            pid, observed, child_usage = os.wait4(child.pid, os.WNOHANG)
            if pid:
                status, usage = os.waitstatus_to_exitcode(observed), child_usage
                child.returncode = status
            else:
                try:
                    actual = Path("/proc") / str(child.pid) / "cgroup"
                    if actual.read_text(encoding="ascii").strip() != "0::/" + str(group.relative_to(CGROUP_ROOT)):
                        ambiguous = True
                        break
                    placement_seen = True
                except (OSError, UnicodeError):
                    pass  # A fast exit can race the placement read; do not invent a measurement.
        if status is not None and eof:
            break
        if time.monotonic() >= deadline:
            ambiguous = True
            if args.mode == "setup" and status is None:
                # Public-only command has no private proving worker. Kill this PID only.
                child.kill()
                _, observed, usage = os.wait4(child.pid, 0)
                status = os.waitstatus_to_exitcode(observed)
                child.returncode = status
            # Wrapped deadline ambiguity never invokes group kill or deletes scratch.
            break
        for key, _ in selector.select(0.1):
            chunk = os.read(key.fd, 8192)
            if not chunk:
                eof = True
                selector.unregister(child.stdout)
            elif not overflow and len(output) + len(chunk) <= OUTPUT_LIMIT:
                output.extend(chunk)
            else:
                overflow = True
                output.clear()
    selector.close()
    elapsed = time.monotonic() - started
    final = snapshot(group)  # This keeper is still alive: cgroup cannot be collected yet.
    child.stdout.close()
    rss = int(usage.ru_maxrss) * 1024 if usage is not None else None
    accounting = normalize_accounting(final, sampled, rss)
    if losses or not placement_seen:
        accounting["status"], accounting["whole_scope_peak_bytes"] = UNMEASURED, UNMEASURED
        accounting["errors"].append("sampler loss or producer placement not observed")
    try:
        remaining = {int(pid) for pid in (group / "cgroup.procs").read_text(encoding="ascii").split()}
        remaining.discard(os.getpid())
        # Exclude only a still-live launcher, not workers; scope argv is not sampled.
        parent = os.getppid()
        try:
            if Path(os.readlink(Path("/proc") / str(parent) / "exe")) == Path("/usr/bin/systemd-run"):
                remaining.discard(parent)
        except OSError:
            pass
        ambiguous = ambiguous or bool(remaining)
    except (OSError, ValueError):
        remaining, ambiguous = None, True
    value, output_error = None, None
    if status == 0 and not overflow and not ambiguous:
        try:
            value = validate_output(bytes(output), args)
        except BenchmarkError as error:
            output_error = str(error)
    limit = limit_status(final)
    outcome = outcome_status(args.mode, status, value is not None, limit, ambiguous)
    if outcome in ("PUBLIC_SETUP_ONLY", "ACTUAL_WRAPPED_CAPSULE") and accounting["status"] != "MEASURED":
        outcome = "BENCHMARK_UNMEASURED"
    return {"kind": "owner_proof_benchmark", "status": outcome, "mode": args.mode,
            "operation": "creation" if args.mode == "wrapped" else "public_program_setup",
            "proof_certificate": False,
            "financial_execution": False, "strict_matching_privacy": False,
            "all_mode_qualification": False, "program_identity": "UNVERIFIED",
            "source_qualification": "UNVERIFIED", "setup_qualification": "UNVERIFIED",
            "cpu_user_seconds": usage.ru_utime if usage is not None else UNMEASURED,
            "cpu_system_seconds": usage.ru_stime if usage is not None else UNMEASURED,
            "unit": unit, "scope_placement": "VERIFIED" if placement_seen else UNMEASURED,
            "controllers": controllers, "limits": {"memory_max_bytes": args.memory_max,
                "memory_swap_max_bytes": 0, "tasks_max": TASKS_MAX,
                "local_reserve_bytes": args.reserve_memory, "worker_timeout_seconds": args.timeout_seconds,
                "wrapped_cap_policy": "strictly above8GiB, conservative safety policy NOT measured minimum"},
            "environment": {"kernel": platform.release(), "machine": platform.machine(),
                "logical_cpus": os.cpu_count(), "load_average": os.getloadavg(), "memory_bytes": envelope},
            "public_artifacts": identities, "elf_sha256": args.elf_sha256, "program_vkey": args.program_vkey,
            "elapsed_seconds": elapsed, "runner_exit_code": status if status is not None else UNMEASURED,
            "failure_stage": None if outcome in ("PUBLIC_SETUP_ONLY", "ACTUAL_WRAPPED_CAPSULE") else
                ("public_light_setup" if args.mode == "setup" else "synthetic_creation_runner"),
            "inner_failure_stage": UNMEASURED, "limit_status": limit, "accounting": accounting,
            "samples": samples, "sample_losses": losses, "sampling_interval_seconds": 0.1,
            "sampled_file_including_shmem_max_bytes": file_max if samples > losses else UNMEASURED,
            "sampled_shmem_subset_max_bytes": shmem_max if samples > losses else UNMEASURED,
            "owned_remaining_processes": len(remaining) if remaining is not None else UNMEASURED,
            "private_root": "RETAINED_CALLER_OWNED", "private_scratch_disk_bytes": UNMEASURED,
            "shared_memory_cleanup": "UNQUALIFIED; counters do not prove erasure or unlink",
            "diagnostics": "NOT_CAPTURED", "output_error": output_error,
            "public_runner_result": value}


def emit(value):
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def failure(args, category, unit=None):
    return {"kind": "owner_proof_benchmark", "status": "REFUSED_OR_AMBIGUOUS_FAILURE",
            "mode": args.mode, "reason": category, "unit": unit, "proof_certificate": False,
            "financial_execution": False, "strict_matching_privacy": False,
            "all_mode_qualification": False, "accounting": {"status": UNMEASURED,
                "whole_scope_peak_bytes": UNMEASURED}, "private_root": "RETAINED_CALLER_OWNED"}


def read_public_report(stream):
    raw = stream.read(2 * OUTPUT_LIMIT + 1)
    if len(raw) > 2 * OUTPUT_LIMIT:
        raise BenchmarkError("benchmark public report exceeded bound; scope retained")
    return raw


def main(argv=None):
    args = parse_args(argv)
    unit = os.environ.get("Z2Z_OWNER_BENCH_SCOPE")
    try:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise BenchmarkError("requires non-root Linux user systemd and cgroup v2")
        envelope = parse_meminfo(Path("/proc/meminfo").read_text(encoding="ascii"))
        reason = check_envelope(args.mode, args.memory_max, args.reserve_memory, envelope.get("MemAvailable"))
        if reason:
            raise BenchmarkError(reason)
        if unit is not None:
            report = measure(args, unit)
            emit(report)
            return 0 if report["status"] in ("PUBLIC_SETUP_ONLY", "ACTUAL_WRAPPED_CAPSULE") else 1
        unit = "z2z-owner-bench-" + uuid.uuid4().hex + ".scope"
        environment = {key: os.environ[key] for key in ("HOME", "PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
                       if key in os.environ}
        environment["Z2Z_OWNER_BENCH_SCOPE"] = unit
        child = subprocess.Popen(scope_command(args, unit), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
        # Close on overflow without waiting on or killing a possibly live scope.
        try:
            raw = read_public_report(child.stdout)
        finally:
            child.stdout.close()
        child.wait()
        report = strict_json(raw)
        if not isinstance(report, dict) or report.get("kind") != "owner_proof_benchmark" or report.get("unit") != unit:
            raise BenchmarkError("transient scope failed without a validated public report")
        emit(report)
        return 0 if child.returncode == 0 and report.get("status") in (
            "PUBLIC_SETUP_ONLY", "ACTUAL_WRAPPED_CAPSULE") else 1
    except BenchmarkError as error:
        emit(failure(args, str(error), unit))
    except KeyboardInterrupt:
        emit(failure(args, "interrupted; scope may still be active, no worker killed or private cleanup attempted", unit))
    except (OSError, ValueError, subprocess.SubprocessError):
        emit(failure(args, "local input/controller/runner unavailable; no private cleanup attempted", unit))
    return 1


if __name__ == "__main__":
    sys.exit(main())
