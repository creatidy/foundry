import hashlib
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

import image_build_executor as e
import image_provenance as p


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class GitManifestTests(unittest.TestCase):
    def test_verified_objects_and_packaging_mapping(self):
        objects = {}
        def add(kind, data):
            oid = hashlib.sha1((kind + " " + str(len(data))).encode() + b"\0" + data).hexdigest()
            objects[(kind, oid)] = data
            return oid
        def tree(entries):
            return add("tree", b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                                        for mode, name, oid in entries))
        blob = add("blob", b"package")
        policy = add("blob", b"policy")
        package = tree([(b"100644", b"__init__.py", blob)])
        examples = tree([(b"100644", b"selector-policy.json", policy)])
        root = tree([(b"40000", b"scarcity_router", package), (b"40000", b"examples", examples)])
        commit = add("commit", b"tree " + root.encode() + b"\n\nmessage\n")
        def run(args):
            return objects[(args[-2], args[-1])]
        with patch.object(p, "NEW_SR", commit):
            result = e.git_manifest(run, "/repo", commit, "sr")
            self.assertEqual(result, {"scarcity_router/__init__.py": hashlib.sha256(b"package").hexdigest(),
                                      "scarcity_router/default-selector-policy.json": hashlib.sha256(b"policy").hexdigest()})
            objects[("blob", blob)] = b"tampered"
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                e.git_manifest(run, "/repo", commit, "sr")

    def test_reject_unknown_revision_before_runner(self):
        with self.assertRaises(ValueError):
            e.git_manifest(lambda _: self.fail("unexpected command"), "/repo", "0" * 40, "sr")

    def test_mi_src_directory_maps_to_installed_root(self):
        objects = {}
        def obj(kind, data):
            oid = hashlib.sha1((kind + " " + str(len(data))).encode() + b"\0" + data).hexdigest()
            objects[(kind, oid)] = data
            return oid
        def tree(name, oid, mode=b"40000"):
            return obj("tree", mode + b" " + name + b"\0" + bytes.fromhex(oid))
        blob = obj("blob", b"mi")
        package = tree(b"__init__.py", blob, b"100644")
        src = tree(b"model_intelligence", package)
        root = tree(b"src", src)
        commit = obj("commit", b"tree " + root.encode() + b"\n\nmessage\n")
        with patch.object(p, "MI", commit):
            self.assertEqual(e.git_manifest(lambda a: objects[(a[-2], a[-1])], "/repo", commit, "mi"),
                             {"model_intelligence/__init__.py": hashlib.sha256(b"mi").hexdigest()})


class DockerExecutorTests(unittest.TestCase):
    def test_build_requires_separate_authorization(self):
        with patch.object(e, "InstalledProject") as project:
            with self.assertRaises(ValueError):
                e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                 build_authorization="")
            project.assert_not_called()

    def test_archive_rejects_unknown_and_duplicate_paths(self):
        good = archive([("scarcity_router/__init__.py", b"ok")])
        self.assertEqual(e._tar_files(good, "scarcity_router"),
                         {"scarcity_router/__init__.py": hashlib.sha256(b"ok").hexdigest()})
        for entries in [[("../escape", b"x")], [("scarcity_router/a", b"x"), ("scarcity_router/a", b"y")],
                        [("scarcity_router/../bad", b"x")],
                        [("scarcity_router/__pycache__/bad.pyc", b"x")]]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                e._tar_files(archive(entries), "scarcity_router")

    def test_mock_build_and_stopped_inspection(self):
        image = "sha256:" + "b" * 64
        base = "sha256:" + "a" * 64
        cid = "c" * 64
        source = (Path(__file__).resolve().parents[1] / "Dockerfile.mi").read_bytes()
        definition = p.dockerfile(source, p.NEW_SR, base)
        direct = json.dumps({"url": p.MI_URL, "vcs_info": {"vcs": "git", "commit_id": p.MI}}).encode()
        with patch.object(e, "InstalledProject") as cls:
            project = cls.return_value
            project.socket_path = Path("/private/docker.sock")
            project.token = "token"
            calls = []
            def docker(*args, **kwargs):
                calls.append(args)
                if args[:2] == ("image", "inspect"):
                    if args[2].startswith("python:"):
                        return json.dumps([{"Os": "linux", "RepoDigests": ["python@" + base],
                                            "RootFS": {"Layers": ["sha256:" + "d" * 64]}}])
                    return json.dumps([{"Os": "linux", "Id": image,
                                         "Config": {"Labels": {e.IMAGE_LABEL: "token"},
                                                    "Entrypoint": ["python", "-m", "scarcity_router.control_server"],
                                                    "Env": ["PATH=/opt/sr/bin:/usr/bin", "PYTHONDONTWRITEBYTECODE=1",
                                                            "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1"]},
                                        "RootFS": {"Layers": ["sha256:" + "d" * 64]}}])
                if args[:2] == ("image", "ls"):
                    return image
                if args[:2] == ("container", "ls"):
                    return ""
                if args[:2] == ("image", "rm"):
                    return ""
                if args[0] == "build":
                    Path(args[args.index("--iidfile") + 1]).write_text(image)
                    return ""
                if args[0] == "create":
                    return cid
                if args[:2] == ("container", "inspect"):
                    return json.dumps([{"Id": cid, "Image": image, "State": {"Running": False},
                                        "Config": {"Labels": {"org.creatidy.foundry.image-test": "token"}}}])
                if args[0] == "cp":
                    path = args[1].split(":", 1)[1]
                    if path.endswith("/site-packages"):
                        return archive([("site-packages/scarcity_router/__init__.py", b"sr"),
                                        ("site-packages/model_intelligence/__init__.py", b"mi"),
                                        ("site-packages/model_intelligence-0.1.0.dist-info/direct_url.json", direct)])
                    if path.endswith("pyvenv.cfg"):
                        return archive([("pyvenv.cfg", b"include-system-site-packages = false\n")])
                    return archive([("foundry-sr-commit", (p.NEW_SR + "\n").encode())])
                if args[:2] == ("container", "rm"):
                    return ""
                self.fail(repr(args))
            project._docker.side_effect = docker
            with e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved") as ex:
                ex.preflight_base = base
                sr = {"scarcity_router/__init__.py": hashlib.sha256(b"sr").hexdigest()}
                mi = {"model_intelligence/__init__.py": hashlib.sha256(b"mi").hexdigest()}
                self.assertEqual(image, p.verify_build(executor=ex, source=source, revision=p.NEW_SR,
                                                      base_digest=base, expected_sr=sr, expected_mi=mi))
            self.assertEqual(project._verify_engine.call_count, 2)
            self.assertTrue(any(args[0] == "build" and "--no-cache" in args for args in calls))
            self.assertTrue(any(args[0] == "create" and "--network" in args and "none" in args for args in calls))
            self.assertFalse(any(args[0] in ("run", "start", "exec") for args in calls))
            self.assertIn(("container", "rm", cid), calls)
            self.assertIn(("image", "rm", image), calls)
            self.assertIn(b"git -C /src rev-parse HEAD > /tmp/foundry-sr-commit", definition)

    def test_site_packages_rejects_bytecode_and_import_redirection(self):
        direct = json.dumps({"url": p.MI_URL, "vcs_info": {"vcs": "git", "commit_id": p.MI}}).encode()
        good = [("site-packages/scarcity_router/__init__.py", b"sr"),
                ("site-packages/model_intelligence/__init__.py", b"mi"),
                ("site-packages/model_intelligence-0.1.0.dist-info/direct_url.json", direct)]
        sr, mi, evidence = e._site_packages(archive(good))
        self.assertEqual(sr["scarcity_router/__init__.py"], hashlib.sha256(b"sr").hexdigest())
        self.assertEqual(mi["model_intelligence/__init__.py"], hashlib.sha256(b"mi").hexdigest())
        self.assertEqual(evidence["url"], p.MI_URL)
        for name in ("scarcity_router/__pycache__/__init__.cpython-312.pyc",
                     "model_intelligence/evil.pyc", "evil.pth", "evil.egg-link",
                     "sitecustomize.cpython-312-x86_64-linux-gnu.so", "usercustomize/__init__.py",
                     "__pycache__/sitecustomize.cpython-312.pyc", "scarcity_router.py",
                     "model_intelligence.cpython-312-x86_64-linux-gnu.so", "evil.zip", "../escape"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                e._site_packages(archive(good + [("site-packages/" + name, b"bad")]))
        with self.assertRaises(ValueError):
            e._site_packages(archive(good + [good[0]]))
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            link = tarfile.TarInfo("site-packages/alias")
            link.type = tarfile.SYMTYPE
            link.linkname = "scarcity_router"
            tar.addfile(link)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            e._site_packages(stream.getvalue())
        with patch.object(e, "SITE_ARCHIVE_LIMIT", 100):
            with self.assertRaisesRegex(ValueError, "exceeds limit"):
                e._site_packages(archive(good))

    def test_build_verified_derives_manifests_for_real_executor(self):
        with patch.object(e, "InstalledProject"):
            ex = e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            with patch.object(ex, "git_manifest", side_effect=[{"sr": "manifest"}, {"mi": "manifest"}]) as manifest, \
                 patch.object(p, "verify_build", return_value="verified") as verify:
                self.assertEqual("verified", e.build_verified(ex, source=b"source", revision=p.NEW_SR,
                                                               base_digest="digest", sr_repo="/sr", mi_repo="/mi"))
                self.assertEqual(2, manifest.call_count)
                self.assertEqual({"sr": "manifest"}, verify.call_args.kwargs["expected_sr"])
                self.assertEqual({"mi": "manifest"}, verify.call_args.kwargs["expected_mi"])

    def test_python_config_requires_safe_startup_and_isolated_venv(self):
        config = {"Entrypoint": ["python", "-m", "scarcity_router.control_server"],
                  "Env": ["PATH=/opt/sr/bin:/usr/bin", "PYTHONDONTWRITEBYTECODE=1",
                          "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1"]}
        venv = b"include-system-site-packages = false\n"
        e._verify_python_config(config, venv)
        for env in (config["Env"] + ["PYTHONPATH=/tmp"], config["Env"] + ["PYTHONSAFEPATH=0"],
                    config["Env"][:-1], ["PATH=/usr/bin"]):
            with self.subTest(env=env), self.assertRaises(ValueError):
                e._verify_python_config({**config, "Env": env}, venv)
        for bad in (b"", b"include-system-site-packages = true\n", venv + venv):
            with self.subTest(venv=bad), self.assertRaises(ValueError):
                e._verify_python_config(config, bad)

    def test_cleanup_refuses_uncertain_build_completion(self):
        with patch.object(e, "InstalledProject") as cls:
            ex = e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp = object()
            ex.attempted = True
            ex.built = None
            with self.assertRaisesRegex(ValueError, "completion is uncertain"):
                ex.cleanup()
            cls.return_value._docker.assert_not_called()

    def test_cleanup_refuses_tagged_or_referenced_images(self):
        image = "sha256:" + "b" * 64
        with patch.object(e, "InstalledProject") as cls:
            project = cls.return_value
            project.token = "token"
            ex = e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp = object()
            ex.attempted = True
            ex.built = image
            info = {"Id": image, "Config": {"Labels": {e.IMAGE_LABEL: "token"}}, "RepoTags": ["shared:latest"]}
            def docker(*args, **kwargs):
                if args[:2] == ("image", "ls"):
                    return image
                if args[:2] == ("image", "inspect"):
                    return json.dumps([info])
                if args[:2] == ("container", "ls"):
                    return "container-id" if any("ancestor=" in arg for arg in args) else ""
                self.fail("unexpected deletion " + repr(args))
            project._docker.side_effect = docker
            with self.assertRaisesRegex(ValueError, "referenced"):
                ex.cleanup()
            info["RepoTags"] = []
            with self.assertRaisesRegex(ValueError, "with containers"):
                ex.cleanup()

    def test_preflight_checks_effective_limits_and_cleans_owned_probe(self):
        base = "sha256:" + "a" * 64
        image = "sha256:" + "b" * 64
        cid = "c" * 64
        with patch.object(e, "InstalledProject") as cls:
            project = cls.return_value
            project.token = "test-token"
            ex = e.DockerExecutor(socket_path="/run/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp = object()
            state = {"Running": False, "ExitCode": 0}
            item = {"Id": cid, "Image": image, "State": state,
                    "Config": {"Labels": {e.PREFLIGHT_LABEL: "test-token"}},
                    "HostConfig": {"NetworkMode": "none", "Memory": 536870912, "MemorySwap": 536870912,
                                   "NanoCpus": 1000000000, "PidsLimit": 128,
                                   "ReadonlyRootfs": True, "Privileged": False, "CgroupnsMode": "private"}}
            evidence = {"memory": "536870912", "swap": "0", "pids": "128", "cpu": "100000 100000",
                        "pid": 1, "self_cgroup": "0::/", "pid1_cgroup": "0::/",
                        "cgroup_mounts": ["29 23 0:27 / /sys/fs/cgroup ro - cgroup2 cgroup rw"],
                        "available": 11 * 1024**3}
            calls = []
            def docker(*args, **kwargs):
                calls.append(args)
                if args[:2] == ("image", "inspect"):
                    return json.dumps([{"Id": image, "Os": "linux", "RepoDigests": ["python@" + base]}])
                if args[0] == "create":
                    return cid
                if args[:2] == ("container", "inspect"):
                    return json.dumps([item])
                if args[:2] == ("start", "--attach"):
                    return json.dumps(evidence)
                if args[:2] == ("container", "rm"):
                    return ""
                self.fail(repr(args))
            project._docker.side_effect = docker
            self.assertEqual(ex.preflight(base_digest=base), evidence)
            self.assertEqual(ex.preflight_base, base)
            self.assertFalse(ex.probe_uncertain)
            self.assertIn(("container", "rm", cid), calls)
            create = next(a for a in calls if a[0] == "create")
            self.assertIn("none", create)
            self.assertIn("never", create)
            self.assertEqual("private", create[create.index("--cgroupns") + 1])
            evidence["swap"] = "max"
            with self.assertRaisesRegex(ValueError, "effective cgroup"):
                ex.preflight(base_digest=base)
            self.assertIsNone(ex.preflight_base)
            evidence["swap"] = "0"
            for key in ("self_cgroup", "pid1_cgroup", "cgroup_mounts"):
                original = evidence[key]
                evidence[key] = None
                with self.subTest(missing=key), self.assertRaisesRegex(ValueError, "effective cgroup"):
                    ex.preflight(base_digest=base)
                self.assertIsNone(ex.preflight_base)
                self.assertFalse(ex.probe_uncertain)
                evidence[key] = original
            calls.clear()
            def timeout(*args, **kwargs):
                if args[:2] == ("start", "--attach"):
                    raise TimeoutError("probe timed out")
                return docker(*args, **kwargs)
            project._docker.side_effect = timeout
            with self.assertRaises(TimeoutError):
                ex.preflight(base_digest=base)
            self.assertNotIn(("container", "rm", cid), calls)
            self.assertTrue(ex.probe_uncertain)
            with self.assertRaisesRegex(ValueError, "probe cleanup is uncertain"):
                ex.cleanup()
            self.assertNotIn(("container", "rm", cid), calls)

    def test_probe_attribution_rejects_unrelated_or_ambiguous_cgroups(self):
        compile(e.PROBE, "<preflight-probe>", "exec")
        for path in ("/proc/self/cgroup", "/proc/1/cgroup", "/proc/self/mountinfo"):
            self.assertIn(path, e.PROBE)
        valid = {"pid": 1, "self_cgroup": "0::/", "pid1_cgroup": "0::/",
                 "cgroup_mounts": ["29 23 0:27 / /sys/fs/cgroup ro - cgroup2 cgroup rw"]}
        self.assertTrue(e._probe_cgroup_attributed(valid))
        for changes in ({"pid": 2}, {"pid": True}, {"self_cgroup": "0::/other"},
                        {"pid1_cgroup": "0::/other"}, {"pid1_cgroup": None},
                        {"cgroup_mounts": []}, {"cgroup_mounts": ["invalid"]},
                        {"cgroup_mounts": ["29 23 0:27 /ancestor /sys/fs/cgroup ro - cgroup2 cgroup rw"]},
                        {"cgroup_mounts": ["29 23 0:27 / /sys/fs/cgroup ro - tmpfs tmpfs rw"]},
                        {"cgroup_mounts": valid["cgroup_mounts"] * 2}):
            with self.subTest(changes=changes):
                self.assertFalse(e._probe_cgroup_attributed({**valid, **changes}))

    def test_preflight_requires_explicit_private_cgroup_namespace(self):
        base, image, cid = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "c" * 64
        with patch.object(e, "InstalledProject") as cls:
            project = cls.return_value
            project.token = "test-token"
            ex = e.DockerExecutor(socket_path="/run/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp = object()
            item = {"Id": cid, "Image": image, "State": {"Running": False},
                    "Config": {"Labels": {e.PREFLIGHT_LABEL: "test-token"}},
                    "HostConfig": {"NetworkMode": "none", "Memory": 536870912, "MemorySwap": 536870912,
                                   "NanoCpus": 1000000000, "PidsLimit": 128,
                                   "ReadonlyRootfs": True, "Privileged": False, "CgroupnsMode": "host"}}
            def docker(*args, **kwargs):
                if args[:2] == ("image", "inspect"):
                    return json.dumps([{"Id": image, "Os": "linux", "RepoDigests": ["python@" + base]}])
                if args[0] == "create":
                    return cid
                if args[:2] == ("container", "inspect"):
                    return json.dumps([item])
                self.fail("unexpected start or cleanup: " + repr(args))
            project._docker.side_effect = docker
            with self.assertRaisesRegex(ValueError, "settings unverified"):
                ex.preflight(base_digest=base)
            self.assertIsNone(ex.preflight_base)
            self.assertTrue(ex.probe_uncertain)
            with self.assertRaisesRegex(ValueError, "probe cleanup is uncertain"):
                ex.cleanup()

    def test_build_rejects_missing_preflight(self):
        base = "sha256:" + "a" * 64
        source = (Path(__file__).resolve().parents[1] / "Dockerfile.mi").read_bytes()
        with patch.object(e, "InstalledProject"):
            ex = e.DockerExecutor(socket_path="/run/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp = object()
            with self.assertRaisesRegex(ValueError, "preflight"):
                ex.build(dockerfile=p.dockerfile(source, p.NEW_SR, base), timeout=p.MAX_SECONDS,
                         output_limit=p.MAX_OUTPUT)

    def test_build_admits_only_definitions_from_reviewed_product_bytes(self):
        base = "sha256:" + "a" * 64
        source = (Path(__file__).resolve().parents[1] / "Dockerfile.mi").read_bytes()
        actual = p.product_revision(source)
        with patch.object(e, "InstalledProject") as cls:
            ex = e.DockerExecutor(socket_path="/private/docker.sock", engine_id="engine", authorization="approved",
                                  build_authorization="disposable-linux-image-build-approved")
            ex.temp, ex.preflight_base = object(), base
            cls.return_value._docker.side_effect = RuntimeError("mock inspection reached")
            for source_revision in p.DOCKERFILE_SHA256:
                variant = source.replace(actual.encode(), source_revision.encode())
                for revision in p.TEST_SR_REVISIONS:
                    definition = p.dockerfile(variant, revision, base)
                    with self.subTest(source=source_revision, target=revision), patch.object(Path, "read_bytes", return_value=variant):
                        with self.assertRaisesRegex(RuntimeError, "mock inspection reached"):
                            ex.build(dockerfile=definition, timeout=p.MAX_SECONDS, output_limit=p.MAX_OUTPUT)
                        cls.return_value._docker.reset_mock()
                        with self.assertRaises(ValueError):
                            ex.build(dockerfile=definition + b"\nRUN malicious\n", timeout=p.MAX_SECONDS,
                                     output_limit=p.MAX_OUTPUT)
                        cls.return_value._docker.assert_not_called()
                    with patch.object(Path, "read_bytes", return_value=variant + b"\n"):
                        with self.assertRaises(ValueError):
                            ex.build(dockerfile=definition, timeout=p.MAX_SECONDS, output_limit=p.MAX_OUTPUT)
                        cls.return_value._docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
