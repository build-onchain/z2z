"""Fast stdlib checks; never start a prover or a systemd unit."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import copy
import hashlib
import os

MODULE_PATH = Path(__file__).with_name("owner_proof_benchmark.py")
SPEC = importlib.util.spec_from_file_location("owner_proof_benchmark", MODULE_PATH)
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
SPEC.loader.exec_module(bench)

GIB = 1024 ** 3
HASH = "0x6cbd653f6dca5e23e884952ca0d7259aebd258be06591dbc1438e3c49e4a40b2"
PROGRAM = "0x00d55cbb42ddf80edb53f3dbdfc1277f21319fac2c0935d86f5dde4d7e562323"


def arguments(mode="setup"):
    result = ["--mode", mode, "--binary", "/opt/owner/ziquid",
            "--example", "/opt/owner/owner_creation_qualification",
            "--elf", "/opt/owner/owner.elf", "--elf-sha256", HASH,
            "--program-vkey", PROGRAM, "--groth16-artifact-base", "/opt/setup",
            "--private-temp-dir", "/opt/owner/private", "--timeout-seconds", "90",
            "--memory-max", "2GiB", "--reserve-memory", "1GiB"]
    if mode == "wrapped":
        result += ["--release-dir", "/opt/owner/releases", "--backup-key-file", "/opt/owner/backup-key",
                   "--op-id", "0x" + "11" * 32]
    return result

def capsule_result(release_dir):
    deployment = {"chain_id": "31337", "authority": "0x" + "01" * 20,
                  "authority_code": "0x" + "02" * 32, "verifier": "0x" + "03" * 20,
                  "verifier_code": "0x" + "04" * 32, "owner_program": PROGRAM, "schema": 1}
    deployment_frame = (b"Z2Z_SAMECHAIN_DEPLOYMENT\0" + b"\0\1" + (31337).to_bytes(8, "big")
                        + bytes([1]) * 20 + bytes([2]) * 32 + bytes([3]) * 20
                        + bytes([4]) * 32 + bytes.fromhex(PROGRAM[2:]) + b"\0\1")
    frame = (b"Z2Z_SAMECHAIN_RELEASE_BINDING\0" + b"\0\1" + bytes([0x11]) * 32
             + len(deployment_frame).to_bytes(4, "big") + deployment_frame + bytes([4, 0])
             + bytes([6]) * 32 + bytes.fromhex(PROGRAM[2:]) + bytes([7]) * 32
             + (700).to_bytes(8, "big") + b"\0")
    capsule = "11" * 32 + ".release"
    ciphertext = b"generated encrypted-byte rejection fixture; no accepted certificate"
    path = release_dir / capsule
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(ciphertext)
    value = {"kind": "samechain_owner_creation_qualification", "status": "ACTUAL_WRAPPED_CAPSULE",
             "operation": "creation", "fixture": "GENERATED_TEST_DEPLOYMENT_NOT_BACKED_TARGET",
             "expected_deployment": deployment, "elf_sha256": HASH, "program_vkey": PROGRAM,
             "op_id": "0x" + "11" * 32, "binding": "0x" + frame.hex(),
             "binding_digest": "0x" + hashlib.sha256(frame).hexdigest(),
             "release_digest": "0x" + hashlib.sha256(ciphertext).hexdigest(), "capsule": capsule,
             "witness_bytes": 500, "packet_bytes": 400, "elapsed_ms": 1,
             "proof_certificate": False, "financial_execution": False, "strict_matching_privacy": False,
             "sdk_storage_boundary": "UNQUALIFIED_EXTERNAL_DEV_SHM_RAII_RETENTION"}
    value.update({field: "UNVERIFIED" for field in bench.UNVERIFIED_FIELDS})
    return value


class ArgumentTests(unittest.TestCase):
    def test_wrapped_requires_capsule_arguments_without_affecting_setup(self):
        bench.parse_args(arguments("setup"))
        for flag in ("--release-dir", "--backup-key-file", "--op-id"):
            argv = arguments("wrapped")
            at = argv.index(flag)
            del argv[at:at + 2]
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                bench.parse_args(argv)

    def test_explicit_binary_sizes_normalize_without_implicit_run_mode(self):
        args = bench.parse_args(arguments("wrapped"))
        self.assertEqual(args.memory_max, 2 * GIB)
        self.assertEqual(args.reserve_memory, GIB)
        argv = arguments()
        argv[argv.index("--memory-max") + 1] = "2147483648"
        self.assertEqual(bench.parse_args(argv).memory_max, 2 * GIB)

    def test_rejects_witness_shell_trailing_and_missing_limits(self):
        for extra in (["--witness-stdin"], ["--command", "sh -c true"], ["unused"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                bench.parse_args(arguments() + extra)
        for flag in ("--mode", "--memory-max", "--reserve-memory"):
            argv = arguments()
            at = argv.index(flag)
            del argv[at:at + 2]
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                bench.parse_args(argv)

    def test_rejects_noncanonical_public_pins_timeouts_and_sizes(self):
        bad = {
            "--elf-sha256": ["0x01", "0x" + "00" * 32, "0x" + "gg" * 32],
            "--program-vkey": ["0x" + "ff" * 32,
                "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"],
            "--timeout-seconds": ["0", "86401", "NaN"],
            "--memory-max": ["0", "infinity", "1.5GiB", "-1"],
        }
        for flag, values in bad.items():
            for value in values:
                argv = arguments()
                argv[argv.index(flag) + 1] = value
                with self.subTest(flag=flag, value=value), self.assertRaises(SystemExit):
                    bench.parse_args(argv)


class EnvelopeTests(unittest.TestCase):
    def test_setup_cap_and_explicit_local_reserve_must_fit_available_not_total(self):
        self.assertIsNone(bench.check_envelope("setup", 2 * GIB, GIB, 4 * GIB))
        for cap, reserve, available in [(4 * GIB, GIB, 4 * GIB),
                                         (GIB, 0, 4 * GIB),
                                         (GIB, GIB, None)]:
            with self.subTest(cap=cap, reserve=reserve, available=available):
                self.assertIsNotNone(bench.check_envelope("setup", cap, reserve, available))

    def test_loaded_host_and_known_small_oom_caps_never_start_wrapping(self):
        for cap, available in [(4 * GIB, 64 * GIB), (8 * GIB, 64 * GIB),
                               (12 * GIB, 5900000000)]:
            with self.subTest(cap=cap, available=available):
                self.assertIsNotNone(bench.check_envelope("wrapped", cap, GIB, available))
        self.assertIsNone(bench.check_envelope("wrapped", 16 * GIB, 2 * GIB, 32 * GIB))

    def test_meminfo_requires_real_available_counter_and_kib_units(self):
        info = bench.parse_meminfo("MemTotal: 99999 kB\nMemAvailable: 2048 kB\nSwapFree: 7 kB\n")
        self.assertEqual(info["MemAvailable"], 2097152)
        self.assertEqual(info["SwapFree"], 7168)
        self.assertNotIn("MemAvailable", bench.parse_meminfo("MemTotal: 2048 kB\n"))
        for value in ["MemAvailable: -1 kB\n", "MemAvailable: 2 MB\n",
                      "MemAvailable: 1 kB\nMemAvailable: 2 kB\n"]:
            with self.subTest(value=value), self.assertRaises(bench.BenchmarkError):
                bench.parse_meminfo(value)


class AccountingTests(unittest.TestCase):
    def test_shmem_is_already_in_file_and_scope_total_never_added_twice(self):
        counters = {"memory.current": "1048576\n", "memory.peak": "2097152\n",
                    "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
                    "memory.stat": "anon 524288\nfile 262144\nshmem 131072\n",
                    "memory.swap.current": "0\n", "pids.events": "max 0\n"}
        value = bench.normalize_accounting(counters, sampled_current=1572864, rss_peak=1048576)
        self.assertEqual(value["whole_scope_peak_bytes"], 2097152)
        self.assertEqual(value["file_including_shmem_bytes"], 262144)
        self.assertEqual(value["shmem_subset_bytes"], 131072)
        self.assertEqual(value["rss_max_bytes"], 1048576)
        self.assertEqual(value["status"], "MEASURED")

    def test_rss_can_exceed_scope_charges_without_invalidating_kernel_peak(self):
        # Already resident shared pages can be charged to a different cgroup.
        counters = {"memory.current": "524288", "memory.peak": "1048576",
                    "memory.events": "max 0\noom 0\noom_kill 0\n",
                    "memory.stat": "anon 262144\nfile 131072\nshmem 65536\n",
                    "memory.swap.current": "0", "pids.events": "max 0\n"}
        value = bench.normalize_accounting(counters, 786432, 2097152)
        self.assertEqual(value["status"], "MEASURED")
        self.assertEqual(value["whole_scope_peak_bytes"], 1048576)
        self.assertEqual(value["rss_max_bytes"], 2097152)

    def test_missing_or_inconsistent_peak_is_unmeasured_not_false_minimum(self):
        for counters in ({}, {"memory.current": "1000000", "memory.peak": "262144"},
                          {"memory.current": "1", "memory.peak": "1", "memory.stat": ""}):
            value = bench.normalize_accounting(counters, sampled_current=1000000,
                                                rss_peak=633488 * 1024)
            self.assertEqual(value["status"], "UNMEASURED")
            self.assertEqual(value["whole_scope_peak_bytes"], "UNMEASURED")
            self.assertEqual(value["rss_max_bytes"], 648691712)

    def test_malformed_counter_data_cannot_be_silently_normalized_to_zero(self):
        for malformed in ("oom -1\n", "oom 0\noom 1\n", "oom nope\n", "broken\n"):
            with self.subTest(malformed=malformed), self.assertRaises(bench.BenchmarkError):
                bench.parse_counters(malformed)
        value = bench.normalize_accounting({"memory.peak": "max"}, 0, None)
        self.assertEqual(value["whole_scope_peak_bytes"], "UNMEASURED")

    def test_missing_events_does_not_claim_no_limit_and_observed_oom_wins(self):
        self.assertEqual(bench.limit_status({}), "UNMEASURED")
        self.assertEqual(bench.limit_status({"memory.events": "oom 1\noom_kill 1\n"}),
                         "OOM_LIMIT")
        self.assertEqual(bench.limit_status({"memory.events": "max 1\noom 0\noom_kill 0\n",
                                            "pids.events": "max 0\n"}), "MEMORY_LIMIT")

    def test_swap_and_invalid_shared_subset_leave_peak_unmeasured(self):
        counters = {"memory.current": "100", "memory.peak": "200",
                    "memory.events": "max 0\noom 0\noom_kill 0\n",
                    "memory.stat": "anon 50\nfile 20\nshmem 30\n",
                    "memory.swap.current": "0", "pids.events": "max 0\n"}
        self.assertEqual(bench.normalize_accounting(counters, 100, 100)["whole_scope_peak_bytes"],
                         "UNMEASURED")
        counters["memory.stat"] = "anon 50\nfile 20\nshmem 10\n"
        counters["memory.swap.current"] = "1"
        self.assertEqual(bench.normalize_accounting(counters, 100, 100)["whole_scope_peak_bytes"],
                         "UNMEASURED")
        self.assertEqual(bench.limit_status({"memory.events": "max 0\noom 0\noom_kill 0\n",
                                            "pids.events": "max 1\n"}), "TASK_LIMIT")


class OutputAndCustodyTests(unittest.TestCase):
    def test_public_setup_wrong_pin_and_certificate_claim_are_rejected(self):
        args = bench.parse_args(arguments())
        public = {"kind": "samechain_owner_program", "elf_sha256": HASH,
                  "program_vkey": PROGRAM, "evidence": "actual_local_light_program_setup",
                  "proof_certificate": False, "program_identity": "UNVERIFIED",
                  "source_qualification": "UNVERIFIED", "setup_qualification": "UNVERIFIED",
                  "root_eligibility": "UNVERIFIED", "global_unspentness": "UNVERIFIED",
                  "asset_backing": "UNVERIFIED", "finality": "UNVERIFIED",
                  "deployment_profile_qualification": "UNVERIFIED",
                  "financial_execution": False, "strict_matching_privacy": False}
        public["program_vkey"] = "0x" + "01" * 32
        with self.assertRaises(bench.BenchmarkError):
            bench.validate_output(json.dumps(public).encode(), args)
        public["program_vkey"] = PROGRAM
        public["proof_certificate"] = True
        with self.assertRaises(bench.BenchmarkError):
            bench.validate_output(json.dumps(public).encode(), args)

    def test_malformed_duplicate_and_setup_outputs_never_qualify_wrapped_success(self):
        args = bench.parse_args(arguments("wrapped"))
        for output in (b"not json", b'{"proof_certificate":true,"proof_certificate":false}',
                       b'{"kind":"samechain_owner_program","proof_certificate":false}',
                       b'{"kind":"samechain_owner_creation_qualification","proof_certificate":true}'):
            with self.subTest(output=output), self.assertRaises(bench.BenchmarkError):
                bench.validate_output(output, args)

    def test_non_object_and_nonfinite_json_never_produce_a_result(self):
        args = bench.parse_args(arguments())
        for output in (b"null", b"[]", b'{"kind":NaN}', b'{"proof_certificate":Infinity}'):
            with self.subTest(output=output), self.assertRaises(bench.BenchmarkError):
                bench.validate_output(output, args)

    def test_public_report_read_stops_at_limit_without_draining_oversized_data(self):
        report = io.BytesIO(b"x" * 140000)
        with self.assertRaises(bench.BenchmarkError):
            bench.read_public_report(report)
        self.assertEqual(report.tell(), 131073)
        self.assertEqual(bench.read_public_report(io.BytesIO(b"{}")), b"{}")

    def test_ambiguous_failure_and_limits_never_become_proof_success(self):
        for returncode, valid, limit, ambiguity in [(1, False, "NO_LIMIT_OBSERVED", False),
                                                   (0, True, "OOM_LIMIT", False),
                                                   (0, True, "NO_LIMIT_OBSERVED", True)]:
            status = bench.outcome_status("wrapped", returncode, valid, limit, ambiguity)
            self.assertNotEqual(status, "ACTUAL_WRAPPED_CAPSULE")
        self.assertEqual(bench.outcome_status("setup", 0, True, "NO_LIMIT_OBSERVED", False),
                         "PUBLIC_SETUP_ONLY")
        self.assertEqual(bench.outcome_status("wrapped", 0, True, "NO_LIMIT_OBSERVED", False),
                         "ACTUAL_WRAPPED_CAPSULE")

    def test_capsule_metadata_rejects_changed_bindings_pins_and_plaintext_certificate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            args = bench.parse_args(arguments("wrapped"))
            args.release_dir = root
            value = capsule_result(root)
            accepted = bench.validate_output(json.dumps(value).encode(), args)
            self.assertFalse(accepted["proof_certificate"])
            mutations = {
                "binding": value["binding"] + "00", "binding_digest": "0x" + "22" * 32,
                "op_id": "0x" + "22" * 32, "capsule": "../private-capsule",
                "journal": "0x01", "proof": "0x4388a21c", "proof_certificate": True,
                "program_vkey": "0x" + "01" * 32,
            }
            for field, replacement in mutations.items():
                changed = copy.deepcopy(value)
                changed[field] = replacement
                with self.subTest(field=field), self.assertRaises(bench.BenchmarkError):
                    bench.validate_output(json.dumps(changed).encode(), args)
            changed = copy.deepcopy(value)
            changed["expected_deployment"]["chain_id"] = "31338"
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(changed).encode(), args)

    def test_capsule_ciphertext_identity_hash_and_trusted_file_policy_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            args = bench.parse_args(arguments("wrapped"))
            args.release_dir = root
            value = capsule_result(root)
            path = root / value["capsule"]
            path.write_bytes(b"changed ciphertext")
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(value).encode(), args)
            path.chmod(0o644)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(value).encode(), args)
            path.unlink()
            path.symlink_to(root / "absent")
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(value).encode(), args)

    def test_capsule_binding_and_ciphertext_bounds_reject_before_unbounded_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            args = bench.parse_args(arguments("wrapped"))
            args.release_dir = root
            value = capsule_result(root)
            changed = copy.deepcopy(value)
            changed["binding"] = "0x" + "11" * (4096 + 1)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(changed).encode(), args)
            path = root / value["capsule"]
            path.write_bytes(b"x" * 5592)
            value["release_digest"] = "0x" + hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_output(json.dumps(value).encode(), args)

    def test_backup_key_metadata_validation_preserves_generated_key_and_rejects_unsafe_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            key = root / "generated-key"
            fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(b"k" * 32)
            bench.validate_backup_key(key)
            self.assertEqual(key.read_bytes(), b"k" * 32)
            for length in (31, 33):
                key.write_bytes(b"k" * length)
                with self.subTest(length=length), self.assertRaises(bench.BenchmarkError):
                    bench.validate_backup_key(key)
            key.write_bytes(b"k" * 32)
            key.chmod(0o644)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_backup_key(key)
            key.chmod(0o600)
            link = root / "link"
            link.symlink_to(key)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_backup_key(link)
            hardlink = root / "hardlink"
            os.link(key, hardlink)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_backup_key(key)
            hardlink.unlink()
            root.chmod(0o770)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_backup_key(key)

    def test_private_root_policy_checks_metadata_only_and_never_deletes_caller_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            sentinel = root / "unrelated"
            sentinel.write_bytes(b"retained caller data")
            bench.validate_private_root(root)
            self.assertEqual(sentinel.read_bytes(), b"retained caller data")
            root.chmod(0o755)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_private_root(root)
            root.chmod(0o700)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(bench.BenchmarkError):
                bench.validate_private_root(link)
            self.assertTrue(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
