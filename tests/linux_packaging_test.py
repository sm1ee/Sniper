"""Linux packaging contracts. No package installation or Sniper execution."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("linux_package", ROOT / "packaging/linux/package.py")
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)
SOURCE = {"revision": "a" * 40, "dirty": True, "tree_sha256": "b" * 64, "cargo_lock_sha256": "c" * 64}


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sniper-package-contract-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binaries = self.root / "binaries"
        self.binaries.mkdir()
        for name in pkg.BINARIES:
            path = self.binaries / name
            path.write_bytes(pkg.FIXTURE + name.encode() + b"\n")
            path.chmod(0o755)
        self.source_patch = patch.object(pkg, "source_state", return_value=SOURCE)
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        self.record_path = self.root / "record.json"
        self.record_args = argparse.Namespace(
            binaries_dir=str(self.binaries), test_fixtures=True, output=str(self.record_path),
            source_date_epoch=1760000000, toolchain_file=None, dependency_manifest=None, build_command="fixture")
        with contextlib.redirect_stdout(io.StringIO()):
            pkg.record(self.record_args)
        self.args = argparse.Namespace(
            binaries_dir=str(self.binaries), test_fixtures=True, output_dir=str(self.root / "output"),
            build_record=str(self.record_path), archive_only=False, sysroot=None, dpkg_admindir=None)

    def package(self):
        with contextlib.redirect_stdout(io.StringIO()):
            pkg.package(self.args)
        return Path(self.args.output_dir)

    def rewrite_record(self, change):
        value = json.loads(self.record_path.read_text())
        change(value)
        self.record_path.write_text(json.dumps(value))

    def test_complete_archive_deb_layout_integrity_and_root_ownership(self):
        output = self.package()
        archive = next(output.glob("*.tar.gz"))
        self.assertIn("debian13-x86_64-TEST-ONLY", archive.name)
        with tarfile.open(archive) as tar:
            files = {member.name.split("/", 1)[1]: tar.extractfile(member).read()
                     for member in tar.getmembers() if member.isfile()}
            for member in tar.getmembers():
                self.assertFalse(member.issym() or member.islnk())
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertFalse(member.mode & 0o7000)
            for binary in pkg.BINARIES:
                self.assertEqual(files[f"bin/{binary}"], pkg.FIXTURE + binary.encode() + b"\n")
                self.assertEqual(tar.getmember(archive.name.removesuffix(".tar.gz") + "/bin/" + binary).mode, 0o755)
            for name in ("LICENSE", "README.md", "build-manifest.json", "SHA256SUMS", "share/applications/sniper.desktop",
                         "share/icons/hicolor/256x256/apps/sniper.png"):
                self.assertIn(name, files)
            self.verify_checksums(files, "SHA256SUMS")
            manifest = json.loads(files["build-manifest.json"])
            self.assertEqual(manifest["qualification"], "not-qualified")
            self.assertTrue(manifest["build"]["test_fixture"])
            self.assertFalse(manifest["system_libraries_bundled"])
            self.assertEqual(set(manifest["payload_files"]), set(files) - {"build-manifest.json", "SHA256SUMS"})
        deb = next(output.glob("*.deb"))
        control = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(deb)])
        with tarfile.open(fileobj=io.BytesIO(control)) as tar:
            controls = {member.name.removeprefix("./"): tar.extractfile(member).read()
                        for member in tar.getmembers() if member.isfile()}
        self.assertEqual(set(controls), {"control", "md5sums"})
        self.assertIn(b"Package: sniper-packaging-fixture\n", controls["control"])
        self.assertIn(b"Architecture: amd64\n", controls["control"])
        self.assertIn(b"Maintainer: sm1ee <sm1ee@users.noreply.github.com>\n", controls["control"])
        self.assertIn(b"TEST FIXTURE ONLY", controls["control"])
        data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(deb)])
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            files = {member.name.removeprefix("./"): tar.extractfile(member).read()
                     for member in tar.getmembers() if member.isfile()}
            for member in tar.getmembers():
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertFalse(member.issym() or member.islnk())
            for binary in pkg.BINARIES:
                self.assertIn(f"usr/bin/{binary}", files)
                self.assertEqual(tar.getmember(f"./usr/bin/{binary}").mode, 0o755)
        self.assertEqual(set(files), {
            *(f"usr/bin/{binary}" for binary in pkg.BINARIES),
            "usr/share/applications/sniper.desktop", "usr/share/icons/hicolor/256x256/apps/sniper.png",
            *(f"usr/share/doc/sniper/{name}" for name in ("LICENSE", "README.md", "build-manifest.json", "SHA256SUMS")),
        })
        self.verify_checksums(files, "usr/share/doc/sniper/SHA256SUMS")
        for line in controls["md5sums"].decode().splitlines():
            checksum, name = line.split("  ", 1)
            self.assertEqual(hashlib.md5(files[name], usedforsecurity=False).hexdigest(), checksum)
        for sidecar in output.glob("*.sha256"):
            checksum, name = sidecar.read_text().strip().split("  ", 1)
            self.assertEqual(pkg.digest(output / name), checksum)
        external = json.loads((output / "build-manifest.json").read_text())
        self.assertEqual(set(external["artifacts"]), {archive.name, deb.name})

    def verify_checksums(self, files, manifest_name):
        checked = set()
        for line in files[manifest_name].decode().splitlines():
            checksum, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), checksum)
            checked.add(name)
        self.assertEqual(checked, set(files) - {manifest_name})

    def test_repack_is_deterministic_and_never_overwrites(self):
        first = self.package()
        with self.assertRaisesRegex(ValueError, "existing output"):
            self.package()
        self.args.output_dir = str(self.root / "second")
        second = self.package()
        self.assertEqual(pkg.file_manifest(first), pkg.file_manifest(second))
        with self.assertRaisesRegex(ValueError, "existing output"):
            pkg.record(self.record_args)

    def test_archive_only_does_not_call_dpkg_dependency_tools(self):
        self.args.archive_only = True
        with patch.object(pkg, "deb_dependencies", side_effect=AssertionError("must not resolve")):
            output = self.package()
        self.assertFalse(list(output.glob("*.deb")))
        self.assertEqual(json.loads((output / "build-manifest.json").read_text())["dependency_resolution"], "not-run")

    def test_input_change_during_copy_is_rejected_before_publishing(self):
        original_copy = pkg.copy_file

        def mutate_then_copy(source, target, executable=False):
            if source.name == "sniper":
                source.write_bytes(b"changed after validation")
            original_copy(source, target, executable)

        with patch.object(pkg, "copy_file", side_effect=mutate_then_copy):
            with self.assertRaisesRegex(ValueError, "changed during staging"):
                self.package()
        self.assertFalse(Path(self.args.output_dir).exists())

    def test_source_change_during_packaging_cannot_publish_mixed_inputs(self):
        with patch.object(pkg, "source_state", side_effect=[SOURCE, {}]):
            with self.assertRaisesRegex(ValueError, "source changed during packaging"):
                self.package()
        self.assertFalse(Path(self.args.output_dir).exists())

    def test_real_record_requires_correct_toolchain_and_debian_inventory(self):
        self.record_args.output = str(self.root / "real-record.json")
        self.record_args.test_fixtures = False
        with self.assertRaisesRegex(ValueError, "real inputs require"):
            pkg.record(self.record_args)
        toolchain = self.root / "toolchain.txt"
        dependencies = self.root / "packages.tsv"
        toolchain.write_text("rustc 1.99.0\nhost: aarch64-unknown-linux-gnu\n")
        dependencies.write_text("libc6\t2.41-12\tamd64\n")
        self.record_args.toolchain_file = str(toolchain)
        self.record_args.dependency_manifest = str(dependencies)
        self.record_args.build_command = "cargo build --locked --release --bins"
        with self.assertRaisesRegex(ValueError, "Linux x86_64"):
            pkg.record(self.record_args)
        toolchain.write_text("rustc 1.99.0\nhost: x86_64-unknown-linux-gnu\n")
        with self.assertRaisesRegex(ValueError, "missing libgtk-3-0t64"):
            pkg.record(self.record_args)
        self.assertFalse(Path(self.record_args.output).exists())

    def test_fixture_mode_cannot_disguise_arbitrary_executables(self):
        (self.binaries / "sniper").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "only inert"):
            self.package()

    def test_accepted_dependency_evidence_is_sealed_into_artifacts(self):
        self.args.test_fixtures = False
        self.rewrite_record(lambda record: record.update(test_fixture=False))
        evidence = [{"kind": "test-evidence", "diagnostic": pkg.LIBC_DIVERSION_DIAGNOSTIC}]
        with patch.object(pkg, "inspect_elf", return_value={"needed": ["libwebkit2gtk-4.1.so.0"]}), \
                patch.object(pkg, "deb_dependencies", return_value=("libc6, libwebkit2gtk-4.1-0", evidence)):
            output = self.package()
        self.assertEqual(json.loads((output / "build-manifest.json").read_text())["dependency_diagnostics"], evidence)
        with tarfile.open(next(output.glob("*.tar.gz"))) as archive:
            member = next(member for member in archive.getmembers() if member.name.endswith("/build-manifest.json"))
            self.assertEqual(json.load(archive.extractfile(member))["dependency_diagnostics"], evidence)
        data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(next(output.glob("*.deb")))])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.getmember("./usr/share/doc/sniper/build-manifest.json")
            self.assertEqual(json.load(archive.extractfile(member))["dependency_diagnostics"], evidence)
        spec = importlib.util.spec_from_file_location("evidence_inspector", ROOT / "packaging/linux/qualification/inspect_candidate.py")
        inspector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inspector)
        # The inspector compares every manifest field across all three copies.
        inspected = inspector.inspect(output, pkg.digest(output / "build-manifest.json"))
        self.assertEqual(inspected["dependency_resolution"], "installed-dpkg-metadata")
        self.assertEqual(inspected["source"], SOURCE)

    def test_real_mode_rejects_fixture_record(self):
        self.args.test_fixtures = False
        with self.assertRaisesRegex(ValueError, "fixture mode"):
            self.package()

    def test_missing_nonexecutable_and_symlink_inputs_are_rejected(self):
        path = self.binaries / "sniper"
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not executable"):
            self.package()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "missing regular"):
            self.package()
        path.symlink_to(self.binaries / "sniper-cli")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.package()

    def test_unsafe_output_paths_do_not_create_files(self):
        for path in ("/usr/sniper-package-output", str(self.root / ".." / "bad"), str(self.root) + "\nunsafe"):
            self.args.output_dir = path
            with self.assertRaises(ValueError):
                self.package()
        link = self.root / "link"
        link.symlink_to(self.root / "real", target_is_directory=True)
        self.args.output_dir = str(link / "out")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.package()
        self.assertFalse((self.root / "real").exists())

    def test_source_binary_target_version_and_epoch_mismatches_are_rejected(self):
        original = self.record_path.read_text()
        major, minor, patch_version = map(int, json.loads(original)["version"].split("."))
        mismatched_version = f"{major}.{minor}.{patch_version + 1}"
        changes = [
            (lambda r: r.update(source={}), "source changed"),
            (lambda r: r["binaries"]["sniper"].update(sha256="0" * 64), "binary changed"),
            (lambda r: r.update(target="ubuntu-x86_64"), "wrong build record target"),
            (lambda r: r.update(version=mismatched_version), "invalid package version"),
            (lambda r: r.update(source_date_epoch=-1), "invalid source date epoch"),
        ]
        for change, error in changes:
            self.record_path.write_text(original)
            self.rewrite_record(change)
            with self.assertRaisesRegex(ValueError, error):
                self.package()
        self.assertFalse(Path(self.args.output_dir).exists())

    def test_wrong_os_architecture_and_distro_are_rejected(self):
        for system, machine, distro in [
            ("Darwin", "x86_64", {"ID": "debian", "VERSION_ID": "13"}),
            ("Linux", "aarch64", {"ID": "debian", "VERSION_ID": "13"}),
            ("Linux", "x86_64", {"ID": "ubuntu", "VERSION_ID": "24.04"}),
            ("Linux", "x86_64", {"ID": "debian", "VERSION_ID": "12"}),
        ]:
            with self.assertRaises(ValueError):
                pkg.host_target(system, machine, distro)

    def test_elf_rejects_nonlinux_wrong_arch_static_and_rpath(self):
        path = self.root / "elf"
        path.write_bytes(b"MZ" + bytes(62))
        with self.assertRaisesRegex(ValueError, "not ELF64"):
            pkg.inspect_elf(path)
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 3, 183)
        path.write_bytes(header)
        with self.assertRaisesRegex(ValueError, "not an x86_64"):
            pkg.inspect_elf(path)
        struct.pack_into("<HH", header, 16, 3, 62)
        header[7] = 9
        path.write_bytes(header)
        with self.assertRaisesRegex(ValueError, "not a Linux"):
            pkg.inspect_elf(path)
        header[7] = 0
        path.write_bytes(header)
        with patch.object(pkg, "run", return_value="no interpreter"):
            with self.assertRaisesRegex(ValueError, "unexpected Linux interpreter"):
                pkg.inspect_elf(path)
        interpreter = "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]"
        for tag in ("RPATH", "RUNPATH"):
            with patch.object(pkg, "run", side_effect=[interpreter, f"({tag}) Library path: [/tmp/sysroot]"]):
                with self.assertRaisesRegex(ValueError, "RPATH/RUNPATH"):
                    pkg.inspect_elf(path)
        with patch.object(pkg, "run", side_effect=[interpreter, "(NEEDED) Shared library: [libc.so.6]", "GLIBC_2.41"]):
            elf = pkg.inspect_elf(path)
        self.assertEqual(elf["needed"], ["libc.so.6"])
        self.assertEqual(elf["glibc_versions"], ["GLIBC_2.41"])

    def test_dependency_tool_uses_official_metadata_and_missing_info_is_fatal(self):
        work = self.root / "deps"
        work.mkdir()
        dependency = "shlibs:Depends=libc6 (>= 2.41), libwebkit2gtk-4.1-0 (>= 2.38)"
        with patch.object(pkg, "dependency_result", return_value=(dependency, [])) as run:
            result = pkg.deb_dependencies(work, pkg.inputs(self.binaries, True))
        self.assertEqual(result, (dependency.split("=", 1)[1], []))
        command = run.call_args.args[0]
        self.assertEqual(command[0:2], ("dpkg-shlibdeps", "-O"))
        self.assertNotIn("--ignore-missing-info", command)
        self.assertEqual(sum(arg.startswith("-e") for arg in command), 3)
        self.assertTrue(run.call_args.kwargs["installed"])
        second = self.root / "bad-deps"
        second.mkdir()
        with patch.object(pkg, "dependency_result", return_value=("shlibs:Depends=libc6", [])):
            with self.assertRaisesRegex(ValueError, "complete native dependency"):
                pkg.deb_dependencies(second, pkg.inputs(self.binaries, True))

    def test_extracted_dependency_metadata_is_explicit_and_read_only(self):
        sysroot = self.root / "sysroot"
        (sysroot / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
        database = self.root / "dpkg"
        database.mkdir()
        (database / "status").write_text("fixture package metadata")
        (database / "info").mkdir()
        (database / "info/format").write_text("1\n")
        work = self.root / "deps-extracted"
        work.mkdir()
        with patch.object(pkg, "dependency_result", return_value=("shlibs:Depends=libc6, libwebkit2gtk-4.1-0", [])) as run, \
                patch.object(pkg, "check_sysroot_libraries") as containment:
            pkg.deb_dependencies(work, pkg.inputs(self.binaries, True), sysroot, database)
        containment.assert_called_once()
        self.assertIn("--admindir=" + str(database), run.call_args.args[0])
        self.assertIn("-l" + str(sysroot / "usr/lib/x86_64-linux-gnu"), run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs["installed"])
        self.assertEqual((database / "status").read_text(), "fixture package metadata")
        self.assertEqual(list(sysroot.rglob("*")), [sysroot / "usr", sysroot / "usr/lib", sysroot / "usr/lib/x86_64-linux-gnu"])
        self.args.sysroot = str(sysroot)
        with self.assertRaisesRegex(ValueError, "supplied together"):
            self.package()

    def test_success_exit_with_dependency_diagnostics_is_fatal(self):
        warnings = [
            "dpkg-shlibdeps: warning: symbol __libc_start_main@GLIBC_2.34 used by sniper found in none of the libraries\n",
            "dpkg-shlibdeps: warning: binary sniper contains an unresolvable reference to symbol __libc_start_main: it's probably a plugin\n",
            "dpkg-shlibdeps: warning: unexpected dependency metadata\n",
        ]
        for warning in warnings:
            completed = subprocess.CompletedProcess(["dpkg-shlibdeps"], 0, "shlibs:Depends=libc6", warning)
            with patch.object(pkg.subprocess, "run", return_value=completed), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "dependency tooling emitted diagnostics"):
                    pkg.run("dpkg-shlibdeps", "-O", clean_stderr=True)
        completed = subprocess.CompletedProcess(["dpkg-shlibdeps"], 0, "shlibs:Depends=libc6", "")
        with patch.object(pkg.subprocess, "run", return_value=completed):
            self.assertEqual(pkg.run("dpkg-shlibdeps", "-O", clean_stderr=True), "shlibs:Depends=libc6")

    def test_sysroot_libraries_cannot_fall_back_or_escape_through_symlinks(self):
        root = self.root / "isolated"
        libraries = root / "usr/lib"
        libraries.mkdir(parents=True)
        elf = {"sniper": {"needed": ["libc.so.6"]}}
        binaries = {"sniper": self.binaries / "sniper"}
        with self.assertRaisesRegex(ValueError, "host fallback is not allowed"):
            pkg.check_sysroot_libraries(root, [libraries], binaries, elf)
        outside = self.root / "outside-libc.so.6"
        outside.write_bytes(b"not a system library")
        link = libraries / "libc.so.6"
        link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes its root"):
            pkg.check_sysroot_libraries(root, [libraries], binaries, elf)
        link.unlink()
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 3, 183)
        link.write_bytes(header)
        with self.assertRaisesRegex(ValueError, "not an x86_64"):
            pkg.check_sysroot_libraries(root, [libraries], binaries, elf)
        struct.pack_into("<HH", header, 16, 3, 62)
        link.write_bytes(header)
        pkg.check_sysroot_libraries(root, [libraries], binaries, elf)

    def test_extracted_mode_rejects_active_host_dependency_overrides(self):
        config = self.root / "host-config"
        config.mkdir()
        override = config / "shlibs.override"
        override.write_text("# default comment\n\n")
        pkg.check_host_overrides(config)
        override.write_text("libc 6 unrelated-host-package\n")
        with self.assertRaisesRegex(ValueError, "active host dependency overrides"):
            pkg.check_host_overrides(config)
        override.write_text("# no active override\n")
        (config / "symbols").mkdir()
        (config / "symbols/libc6:amd64.symbols").write_text("host override")
        with self.assertRaisesRegex(ValueError, "host symbol override"):
            pkg.check_host_overrides(config)

    def test_tar_verifier_rejects_corruption_symlinks_and_duplicate_files(self):
        expected = {"bin/sniper": hashlib.sha256(b"fixture").hexdigest()}

        def payload(kind):
            result = io.BytesIO()
            with tarfile.open(fileobj=result, mode="w") as tar:
                entry = tarfile.TarInfo("bin/sniper")
                entry.uid = entry.gid = 0
                entry.mode = 0o755
                value = b"corrupt" if kind == "corrupt" else b"fixture"
                entry.size = len(value)
                if kind == "symlink":
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "/usr/bin/unrelated"
                    tar.addfile(entry)
                else:
                    tar.addfile(entry, io.BytesIO(value))
                    if kind == "duplicate":
                        tar.addfile(entry, io.BytesIO(value))
            result.seek(0)
            return result

        for kind, error in (("corrupt", "checksum mismatch"), ("symlink", "symlink"), ("duplicate", "duplicate")):
            with self.assertRaisesRegex(ValueError, error):
                pkg.verify_tar(payload(kind), expected)

    def test_failure_keeps_prior_files_and_home_untouched(self):
        home = self.root / "home"
        (home / ".sniper").mkdir(parents=True)
        (home / ".sniper/sentinel").write_text("synthetic session")
        (home / ".profile").write_text("unchanged shell profile")
        before = pkg.file_manifest(home)
        self.args.test_fixtures = False
        self.rewrite_record(lambda record: record.update(test_fixture=False))
        with patch.dict(os.environ, {"HOME": str(home)}):
            with self.assertRaises(ValueError):
                self.package()
        self.assertEqual(pkg.file_manifest(home), before)
        self.assertFalse(Path(self.args.output_dir).exists())

    def test_desktop_and_ci_contracts_do_not_claim_native_gui_qualification(self):
        desktop = (ROOT / "packaging/linux/sniper.desktop").read_text()
        for line in ("Exec=sniper-desktop", "TryExec=sniper-desktop", "Icon=sniper", "Terminal=false", "Type=Application"):
            self.assertIn(line + "\n", desktop)
        for forbidden in ("sudo", "pkexec", "env ", "--no-sandbox"):
            self.assertNotIn(forbidden, desktop)
        workflow = (ROOT / ".github/workflows/linux.yml").read_text()
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("image: rust:1.99.0-trixie", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("actions/setup-node@v6", workflow)
        self.assertIn("node-version: '24'", workflow)
        self.assertIn("cargo test --locked --release", workflow)
        self.assertIn("cargo build --locked --release --bins", workflow)
        runtime = workflow.split("  runtime-debian13-x86_64:", 1)[1]
        self.assertNotIn("\n    container:", runtime)
        self.assertIn("docker run --rm --pull=never --platform linux/amd64", runtime)
        self.assertEqual(runtime.count("--mount "), 3)
        for mount in ("dst=/qa/input,readonly", "dst=/qa/scripts,readonly", "dst=/qa/results"):
            self.assertIn(mount, runtime)
        for forbidden in ("docker.sock", "--privileged", "--security-opt", "--cap-add", "--env-file"):
            self.assertNotIn(forbidden, runtime)
        harness = (ROOT / "packaging/linux/qualification/qualify_ci_lifecycle.py").read_text()
        self.assertIn('("purged", "--purge")', harness)
        self.assertIn('command("apt-get", "install", "--no-install-recommends", "--no-remove"', harness)
        self.assertIn("verify_loader_closures(inventory, command, home, custom_data)", harness)
        for forbidden in ("gh release", "contents: write", "git push", "--no-sandbox", "WEBKIT_DISABLE_SANDBOX"):
            self.assertNotIn(forbidden, workflow)


class GitOwnershipContractsTests(unittest.TestCase):
    """Exercise Git's ownership gate without changing filesystem ownership."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sniper-git-trust-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.global_config = self.home / ".gitconfig"
        self.global_config.write_text("[test]\n\tsentinel = unchanged\n")
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / "xdg"),
                        GIT_CONFIG_GLOBAL=str(self.global_config), GIT_CONFIG_NOSYSTEM="1", LC_ALL="C")
        self.repo = self.root / "trusted-checkout"
        self.other = self.root / "other-checkout"
        for repository in (self.repo, self.other):
            repository.mkdir()
            self.invoke("git", "init", "--quiet", "--initial-branch=main", cwd=repository).check_returncode()
            (repository / "Cargo.lock").write_text("inert lock fixture\n")
            scripts = repository / "packaging/linux"
            scripts.mkdir(parents=True)
            shutil.copyfile(ROOT / "packaging/linux/package.py", scripts / "package.py")
            self.invoke("git", "add", ".", cwd=repository).check_returncode()
            self.invoke("git", "-c", "user.name=Packaging Fixture", "-c", "user.email=test@example.com",
                        "commit", "--quiet", "-m", "Create inert Git fixture", cwd=repository).check_returncode()
        self.env["GITHUB_WORKSPACE"] = str(self.repo)
        self.revision = self.invoke("git", "rev-parse", "HEAD").stdout.strip()
        self.config_before = {path: path.read_bytes() for path in (
            self.global_config, self.repo / ".git/config", self.other / ".git/config")}
        self.ownership_before = {path: (path.stat().st_uid, path.stat().st_gid) for path in self.root.rglob("*")}

    def tearDown(self):
        for path, content in self.config_before.items():
            self.assertEqual(path.read_bytes(), content, f"configuration changed: {path}")
        self.assertFalse((self.home / "xdg").exists(), "Git wrote persistent XDG configuration")
        for path, ownership in self.ownership_before.items():
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), ownership)

    def invoke(self, *args, env=None, cwd=None):
        return subprocess.run(args, env=self.env if env is None else env,
                              cwd=self.repo if cwd is None else cwd,
                              text=True, capture_output=True, check=False)

    def simulated_owner(self, trusted=None):
        env = {**self.env, "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}
        if trusted is not None:
            env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0=str(trusted))
        return env

    def packaging_source_state(self, env):
        script = (
            "import importlib.util,json,sys; "
            "spec=importlib.util.spec_from_file_location('fixture_package',sys.argv[1]); "
            "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
            "print(json.dumps(module.source_state()))"
        )
        return self.invoke(sys.executable, "-B", "-c", script,
                           str(self.repo / "packaging/linux/package.py"), env=env)

    def record_step(self):
        workflow = (ROOT / ".github/workflows/linux.yml").read_text()
        marker = "      - name: Record exact inputs and build candidate artifacts\n"
        before, remaining = workflow.split(marker, 1)
        step, after = remaining.split("      - uses: actions/upload-artifact@v4", 1)
        return before, step, after

    def epoch_prologue(self):
        _, step, _ = self.record_step()
        body = step.split("        run: |\n", 1)[1].split("          mkdir -p dist\n", 1)[0]
        return "\n".join(line[10:] for line in body.splitlines()) + "\n"

    def test_workflow_trust_is_step_scoped_and_exact(self):
        before, step, after = self.record_step()
        for line in ("          export GIT_CONFIG_COUNT=1", "          export GIT_CONFIG_KEY_0=safe.directory",
                     '          export GIT_CONFIG_VALUE_0="$checkout"'):
            self.assertIn(line + "\n", step)
        self.assertNotIn("GIT_CONFIG_", before + after)
        self.assertNotIn("${{ github.workspace }}", step)
        self.assertIn('checkout="$(pwd -P)"', step)
        self.assertIn('if [[ "$checkout" != "$GITHUB_WORKSPACE" ]]; then', step)
        self.assertLess(step.index('if [[ "$checkout" != "$GITHUB_WORKSPACE" ]]; then'),
                        step.index("export GIT_CONFIG_COUNT=1"))
        self.assertNotIn("GIT_TEST_ASSUME_DIFFERENT_OWNER", before + step + after)
        for forbidden in ("git config --global", "git config --system", "safe.directory '*'", "safe.directory=*", "chown ", "chmod "):
            self.assertNotIn(forbidden, step)
        self.assertIn('--source-date-epoch "$source_date_epoch"', step)
        self.assertNotIn('--source-date-epoch "$(git', step)
        self.assertTrue(self.epoch_prologue().startswith("set -euo pipefail\n"))

    def test_ordinary_owned_git_remains_usable_without_override(self):
        result = self.invoke("git", "rev-parse", "HEAD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), self.revision)

    def test_absent_or_wrong_trust_is_rejected_by_git_and_package_children(self):
        for trusted in (None, self.other):
            with self.subTest(trusted=trusted):
                env = self.simulated_owner(trusted)
                for result in (self.invoke("git", "rev-parse", "HEAD", env=env), self.packaging_source_state(env)):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("dubious ownership", result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_exact_trust_reaches_packaging_children_without_trusting_other_checkout(self):
        env = self.simulated_owner(self.repo)
        direct = self.invoke("git", "rev-parse", "HEAD", env=env)
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(direct.stdout.strip(), self.revision)
        result = self.packaging_source_state(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(result.stdout)
        self.assertEqual(state["revision"], self.revision)
        self.assertFalse(state["dirty"])
        self.assertEqual(state["cargo_lock_sha256"], pkg.digest(self.repo / "Cargo.lock"))
        inventory = {"Cargo.lock": pkg.digest(self.repo / "Cargo.lock"),
                     "packaging/linux/package.py": pkg.digest(self.repo / "packaging/linux/package.py")}
        self.assertEqual(state["tree_sha256"], hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest())
        unrelated = self.invoke("git", "rev-parse", "HEAD", env=env, cwd=self.other)
        self.assertNotEqual(unrelated.returncode, 0)
        self.assertIn("dubious ownership", unrelated.stderr)
        # Returning to an untrusted process still rejects this checkout.
        again = self.invoke("git", "rev-parse", "HEAD", env=self.simulated_owner())
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("dubious ownership", again.stderr)

    def test_runtime_workspace_mismatch_fails_before_trust_or_packaging(self):
        script = self.epoch_prologue() + "printf 'LATER-PACKAGING\\n'\n"
        for workspace in (str(self.other), str(self.root / "host-workspace")):
            with self.subTest(workspace=workspace):
                env = {**self.simulated_owner(), "GITHUB_WORKSPACE": workspace}
                result = self.invoke("bash", "-c", script, env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("checkout does not match GITHUB_WORKSPACE", result.stderr)
                self.assertNotIn("LATER-PACKAGING", result.stdout)

    def test_epoch_capture_fails_before_later_packaging_commands(self):
        script = self.epoch_prologue() + "printf 'LATER-PACKAGING:%s\\n' \"$source_date_epoch\"\n"
        success = self.invoke("bash", "-c", script, env=self.simulated_owner())
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertRegex(success.stdout, r"^LATER-PACKAGING:[0-9]+\n$")
        empty = self.root / "empty-checkout"
        empty.mkdir()
        self.invoke("git", "init", "--quiet", "--initial-branch=main", cwd=empty).check_returncode()
        env = {**self.simulated_owner(), "GITHUB_WORKSPACE": str(empty)}
        failed = self.invoke("bash", "-c", script, env=env, cwd=empty)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("fatal:", failed.stderr)
        self.assertNotIn("LATER-PACKAGING", failed.stdout)
        invalid = self.invoke("bash", "-c", "git() { printf 'not-an-epoch\\n'; }\n" + script)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("invalid source timestamp", invalid.stderr)
        self.assertNotIn("LATER-PACKAGING", invalid.stdout)



class LibcDiversionTests(unittest.TestCase):
    # Copied verbatim from CI run 38345012771; this is not a permissive pattern.
    diagnostic = (
        "dpkg-shlibdeps: warning: diversions involved - output may be incorrect\n"
        " diversion by libc6 from: /lib64/ld-linux-x86-64.so.2\n"
        "dpkg-shlibdeps: warning: diversions involved - output may be incorrect\n"
        " diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.usr-is-merged\n"
    )

    def invoke(self, stderr, installed=True, code=0):
        command = ("dpkg-shlibdeps", "-O", "--warnings=symbol-not-found",
                   "-e/stage/usr/bin/sniper", "-e/stage/usr/bin/sniper-cli", "-e/stage/usr/bin/sniper-desktop")
        result = subprocess.CompletedProcess(command, code, "shlibs:Depends=libc6, libwebkit2gtk-4.1-0\n", stderr)
        with patch.object(pkg.subprocess, "run", return_value=result) as process, \
                patch.object(pkg, "verified_libc_diversion", return_value={"verified": True}) as verify, \
                contextlib.redirect_stderr(io.StringIO()):
            answer = pkg.dependency_result(command, Path("/inert-stage"), installed)
            process.assert_called_once_with(command, cwd=Path("/inert-stage"), env=pkg.ENV,
                                            text=True, capture_output=True, check=False)
            return answer, verify.call_count

    def test_exact_installed_warning_retains_evidence_and_command(self):
        self.assertEqual(pkg.LIBC_DIVERSION_DIAGNOSTIC, self.diagnostic)
        (output, evidence), count = self.invoke(self.diagnostic)
        self.assertEqual(output, "shlibs:Depends=libc6, libwebkit2gtk-4.1-0")
        self.assertEqual(evidence, [{"verified": True}])
        self.assertEqual(count, 1)
        self.assertEqual(self.invoke("")[0][1], [])

    def test_unknown_partial_modified_repeated_and_combined_diagnostics_fail(self):
        missing = "dpkg-shlibdeps: warning: symbol __libc_start_main@GLIBC_2.34 used by sniper found in none of the libraries\n"
        plugin = "dpkg-shlibdeps: warning: binary sniper contains an unresolvable reference to symbol __libc_start_main: it's probably a plugin\n"
        for diagnostic in (missing, plugin, "unknown\n", self.diagnostic + missing, missing + self.diagnostic,
                           self.diagnostic + plugin, self.diagnostic + "unknown\n", self.diagnostic * 2,
                           self.diagnostic.replace("by libc6", "by other"), self.diagnostic.replace("/lib64/", "/tmp/"),
                           "\n".join(self.diagnostic.splitlines()[:2]) + "\n", self.diagnostic.rstrip(), " \n"):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(ValueError, "dependency tooling emitted diagnostics"):
                self.invoke(diagnostic)

    def test_extracted_mode_and_nonzero_exit_never_accept_warning(self):
        with self.assertRaisesRegex(ValueError, "dependency tooling emitted diagnostics"):
            self.invoke(self.diagnostic, installed=False)
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(self.diagnostic, code=1)

    def verification(self, change=None):
        loader = Path(pkg.LIBC_CANONICAL_LOADER)
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", header, 16, 3, 62)
        content = bytes(header)
        checksum = hashlib.md5(content, usedforsecurity=False).hexdigest()
        values = {"--listpackage": "libc6", "--truename": pkg.LIBC_DIVERSION,
                  "--show": "install ok installed\tamd64\t2.41-12+deb13u4",
                  "--search": "libc6:amd64: " + str(loader),
                  "--control-show": checksum + "  " + str(loader).lstrip("/") + "\n"}
        change = change or {}
        values.update(change.get("values", {}))
        def command(*args, **kwargs):
            self.assertTrue(kwargs["clean_stderr"])
            self.assertIn(args[0], {"dpkg-divert", "dpkg-query"})
            self.assertNotIn("--add", args)
            return values[args[1]]
        def resolve(path, **kwargs):
            return Path(change.get("resolved", str(loader)))
        with patch.object(pkg, "run", side_effect=command), patch.object(pkg, "check_host_overrides"), \
                patch.object(Path, "resolve", resolve), patch.object(Path, "exists", return_value=change.get("destination", False)), \
                patch.object(Path, "is_symlink", return_value=change.get("dangling_destination", False)), \
                patch.object(Path, "lstat", return_value=argparse.Namespace(st_mode=change.get("mode", 0o100755))), \
                patch.object(Path, "read_bytes", return_value=change.get("content", content)), \
                patch.object(Path, "open", return_value=io.BytesIO(change.get("content", content))), \
                patch.object(pkg, "digest", return_value="a" * 64):
            return pkg.verified_libc_diversion()

    def test_official_diversion_records_readonly_identity_and_checksum(self):
        evidence = self.verification()
        self.assertEqual(evidence["diagnostic"], self.diagnostic)
        self.assertEqual(evidence["canonical_loader"], pkg.LIBC_CANONICAL_LOADER)
        self.assertEqual(evidence["loader_sha256"], "a" * 64)
        self.assertTrue(evidence["destination_absent"])

    def test_diversion_owner_target_destination_and_status_mismatches_fail(self):
        changes = [{"values": {"--listpackage": value}} for value in ("LOCAL", "other", "", "libc6:amd64")]
        changes += [{"values": {"--truename": "/tmp/unexpected"}}, {"destination": True}, {"dangling_destination": True}]
        changes += [{"values": {"--show": value}} for value in ("install ok unpacked\tamd64\t2.41", "install ok installed\ti386\t2.41", "install ok installed\tamd64\t")]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verification(change)

    def test_canonical_file_type_elf_owner_and_checksums_must_match(self):
        changes = [{"resolved": "/tmp/loader"}, {"mode": 0o120777}, {"content": b"not ELF"},
                   {"values": {"--search": "other: " + pkg.LIBC_CANONICAL_LOADER}},
                   {"values": {"--search": "libc6:amd64: " + pkg.LIBC_CANONICAL_LOADER + "\nother: " + pkg.LIBC_CANONICAL_LOADER}},
                   {"values": {"--control-show": ""}}, {"values": {"--control-show": "0" * 32 + "  " + pkg.LIBC_CANONICAL_LOADER.lstrip("/")}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verification(change)

    def test_readonly_validation_command_errors_remain_fatal(self):
        with patch.object(pkg, "check_host_overrides"), patch.object(pkg, "run", side_effect=subprocess.CalledProcessError(2, "dpkg-divert")):
            with self.assertRaises(subprocess.CalledProcessError):
                pkg.verified_libc_diversion()


class NativeDependencyRegressionTests(unittest.TestCase):
    @unittest.skipUnless(all(os.environ.get(name) for name in (
        "SNIPER_PACKAGING_NATIVE_BINARIES", "SNIPER_PACKAGING_SYSROOT", "SNIPER_PACKAGING_DPKG_ADMINDIR")),
        "set the three SNIPER_PACKAGING_* paths to run the real ELF/private-database regression")
    def test_missing_required_native_libc_symbol_fails_closed(self):
        original = pkg.inputs(os.environ["SNIPER_PACKAGING_NATIVE_BINARIES"])
        sysroot = pkg.safe_path(os.environ["SNIPER_PACKAGING_SYSROOT"])
        database = pkg.safe_path(os.environ["SNIPER_PACKAGING_DPKG_ADMINDIR"])
        symbols = database / "info/libc6:amd64.symbols"
        before_symbols = pkg.digest(symbols)
        before_binaries = {name: pkg.digest(path) for name, path in original.items()}
        with tempfile.TemporaryDirectory(prefix="sniper-native-dependency-regression-", dir="/tmp") as temporary:
            root = Path(temporary)
            stage = root / "stage"
            (stage / "DEBIAN").mkdir(parents=True)
            staged = {}
            for name, path in original.items():
                staged[name] = stage / "usr/bin" / name
                pkg.copy_file(path, staged[name], True)
            baseline = root / "baseline"
            baseline.mkdir()
            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics):
                depends, evidence = pkg.deb_dependencies(baseline, staged, sysroot, database)
            self.assertEqual(evidence, [])
            self.assertEqual(diagnostics.getvalue(), "")
            self.assertIn("libc6", depends)
            self.assertIn("libwebkit2gtk-4.1-0", depends)
            private = root / "private-db"
            shutil.copytree(database, private)
            # Reproduce the official diagnostic using only a fresh private
            # database. The installed database and loader are never changed.
            diversion = private / "diversions"
            diversion.write_text(pkg.LIBC_LOADER + "\n" + pkg.LIBC_DIVERSION + "\nlibc6\n")
            reproduced = root / "diversion"
            reproduced.mkdir()
            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics):
                with self.assertRaisesRegex(ValueError, "dependency tooling emitted diagnostics"):
                    pkg.deb_dependencies(reproduced, staged, sysroot, private)
            self.assertEqual(diagnostics.getvalue(), pkg.LIBC_DIVERSION_DIAGNOSTIC)
            diversion.unlink()
            damaged = private / "info/libc6:amd64.symbols"
            lines = damaged.read_text().splitlines(keepends=True)
            removed = [line for line in lines if line.startswith(" __libc_start_main@GLIBC_2.34 ")]
            self.assertEqual(len(removed), 1, "expected exactly one required libc symbol in official metadata")
            damaged.write_text("".join(line for line in lines if line not in removed))
            negative = root / "negative"
            negative.mkdir()
            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics):
                with self.assertRaisesRegex(ValueError, "dependency tooling emitted diagnostics"):
                    pkg.deb_dependencies(negative, staged, sysroot, private)
            self.assertIn("__libc_start_main", diagnostics.getvalue())
        self.assertEqual(pkg.digest(symbols), before_symbols)
        self.assertEqual({name: pkg.digest(path) for name, path in original.items()}, before_binaries)


if __name__ == "__main__":
    unittest.main()
