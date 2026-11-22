"""Build-step checks for services/nli/Dockerfile, run without Docker.

Standard-library only:
    python3 -m unittest services/nli/test_dockerfile.py
    pytest services/nli/test_dockerfile.py

The image is too heavy to build in CI, so these tests pull the RUN commands
out of the Dockerfile and execute them with /bin/sh (the shell Docker uses
for the shell form), with `python` and `pip` on PATH replaced where needed.
They check three things:
  * torch (the wheel alone, not its dependencies) is installed from the
    PyTorch CPU wheel index, at the version requirements.txt pins, before the
    rest of the requirements, and the build fails if a CUDA build of torch
    ends up in the image;
  * a failing model pre-cache fails the build instead of being masked;
  * the NLI_STUB build argument reaches the pre-cache step and skips it.
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
DOCKERFILE = HERE / "Dockerfile"
REQUIREMENTS = HERE / "requirements.txt"
CPU_INDEX = "https://download.pytorch.org/whl/cpu"
PRECACHE_FAILED = "NLI model pre-cache failed"
PRECACHE_SKIPPED = "NLI_STUB=1: skipping the model pre-cache"


def _instructions() -> list[tuple[str, str]]:
    """(KEYWORD, arguments) per Dockerfile instruction, continuations joined."""
    out: list[tuple[str, str]] = []
    buf = ""
    for raw in DOCKERFILE.read_text().splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        keyword, _, args = buf.strip().partition(" ")
        out.append((keyword.upper(), args.strip()))
        buf = ""
    return out


def _run_index(predicate) -> int:
    hits = [
        i
        for i, (kw, args) in enumerate(_instructions())
        if kw == "RUN" and predicate(args)
    ]
    if len(hits) != 1:
        raise AssertionError(f"expected exactly one matching RUN, found {len(hits)}")
    return hits[0]


def _is_requirements_install(args: str) -> bool:
    return "pip install" in args and "-r requirements.txt" in args


def _is_precache(args: str) -> bool:
    return "NLI_MODEL" in args or "precache_model.py" in args


def _is_cpu_index_install(args: str) -> bool:
    return CPU_INDEX in args


def _is_cuda_check(args: str) -> bool:
    return "torch.version.cuda" in args


def _clean_env(**extra: str) -> dict[str, str]:
    # test_app.py sets NLI_STUB=1 in this process at import; the build steps
    # must not inherit it (or any other NLI_* setting) from the test runner.
    env = {k: v for k, v in os.environ.items() if not k.startswith("NLI_")}
    env.pop("PYTHONPATH", None)
    env["HF_HUB_OFFLINE"] = "1"
    env.update(extra)
    return env


def _shim_dir(tmp: pathlib.Path, *, pip_log: pathlib.Path | None = None) -> pathlib.Path:
    """A PATH dir whose `python` is this interpreter and whose `pip` records argv."""
    bindir = tmp / "bin"
    bindir.mkdir()
    # A wrapper, not a symlink: a symlinked venv interpreter would lose the
    # venv's site-packages (python finds pyvenv.cfg next to the invoked path).
    python = bindir / "python"
    python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    python.chmod(0o755)
    if pip_log is not None:
        pip = bindir / "pip"
        pip.write_text(
            "#!/bin/sh\n"
            f'for a in "$@"; do printf "%s\\n" "$a"; done >> "{pip_log}"\n'
            f'printf "%s\\n" "--" >> "{pip_log}"\n'
        )
        pip.chmod(0o755)
    return bindir


def _sh(command: str, *, cwd: pathlib.Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/sh", "-c", command],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _pinned(name: str) -> str:
    for raw in REQUIREMENTS.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith(f"{name}=="):
            return line
    raise AssertionError(f"{name} is not ==-pinned in requirements.txt")


class TorchCpuWheelTest(unittest.TestCase):
    def test_torch_comes_from_the_cpu_index_at_the_pinned_version_first(self):
        cpu = _run_index(_is_cpu_index_install)
        req = _run_index(_is_requirements_install)
        self.assertLess(cpu, req, "the CPU torch install must precede -r requirements.txt")

        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            log = tmp / "pip.log"
            shutil.copy(REQUIREMENTS, tmp / "requirements.txt")
            bindir = _shim_dir(tmp, pip_log=log)
            env = _clean_env(PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
            res = _sh(_instructions()[cpu][1], cwd=tmp, env=env)
            self.assertEqual(res.returncode, 0, res.stderr)
            argv = log.read_text().splitlines()

        self.assertEqual(argv[-1], "--", "pip was called exactly once")
        argv = argv[:-1]
        self.assertIn("install", argv)
        # --index-url (not --extra-index-url) and --no-deps: only the torch
        # wheel comes from this index; torch's dependencies, and everything
        # else, resolve from PyPI in the requirements step.
        self.assertIn("--index-url", argv)
        self.assertNotIn("--extra-index-url", argv)
        self.assertIn("--no-deps", argv)
        self.assertEqual(argv[argv.index("--index-url") + 1], CPU_INDEX)
        # The version is the one requirements.txt pins, read from that file.
        self.assertIn(_pinned("torch"), argv)

    def test_build_fails_when_the_installed_torch_is_a_cuda_build(self):
        check = _run_index(_is_cuda_check)
        self.assertGreater(
            check,
            _run_index(_is_requirements_install),
            "the CUDA check must run after every pip install",
        )
        command = _instructions()[check][1]
        for cuda, want_ok in (("None", True), ("'12.8'", False)):
            with self.subTest(cuda=cuda), tempfile.TemporaryDirectory() as tmp:
                tmp = pathlib.Path(tmp)
                fake = tmp / "site" / "torch"
                fake.mkdir(parents=True)
                (fake / "__init__.py").write_text(
                    textwrap.dedent(
                        f"""
                        import types
                        CUDA = {cuda}
                        __version__ = "2.13.0" + ("+cpu" if CUDA is None else "")
                        version = types.SimpleNamespace(cuda=CUDA)
                        """
                    )
                )
                bindir = _shim_dir(tmp)
                env = _clean_env(
                    PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                    PYTHONPATH=str(tmp / "site"),
                )
                res = _sh(command, cwd=tmp, env=env)
                if want_ok:
                    self.assertEqual(res.returncode, 0, res.stderr)
                else:
                    self.assertNotEqual(res.returncode, 0)
                    self.assertIn("CUDA", res.stderr)


class ModelPrecacheTest(unittest.TestCase):
    def test_a_failing_model_load_fails_the_build(self):
        # A model that cannot load (here: a path that does not exist, offline)
        # must stop the build with the pre-cache's own error, not ship an image
        # without a working model.
        command = _instructions()[_run_index(_is_precache)][1]
        with tempfile.TemporaryDirectory() as tmp:
            bindir = _shim_dir(pathlib.Path(tmp))
            env = _clean_env(
                PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                NLI_MODEL=str(pathlib.Path(tmp) / "no-such-model"),
            )
            res = _sh(command, cwd=HERE, env=env)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn(PRECACHE_FAILED, res.stderr)

    def test_nli_stub_build_arg_reaches_the_precache_and_skips_it(self):
        instructions = _instructions()
        precache = _run_index(_is_precache)
        # Docker only exposes a --build-arg to RUN steps after a matching ARG.
        declared = [
            i
            for i, (kw, args) in enumerate(instructions)
            if kw == "ARG" and re.match(r"NLI_STUB(=|$)", args)
        ]
        self.assertTrue(declared and declared[0] < precache, "ARG NLI_STUB missing before the pre-cache")
        # Build-time only: a stub-built image must not serve stub scores.
        self.assertFalse(
            [a for kw, a in instructions if kw == "ENV" and "NLI_STUB" in a],
            "NLI_STUB must not be baked into the runtime ENV",
        )
        with tempfile.TemporaryDirectory() as tmp:
            bindir = _shim_dir(pathlib.Path(tmp))
            env = _clean_env(
                PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                NLI_STUB="1",
                NLI_MODEL=str(pathlib.Path(tmp) / "no-such-model"),
            )
            res = _sh(instructions[precache][1], cwd=HERE, env=env)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn(PRECACHE_SKIPPED, res.stdout)


if __name__ == "__main__":
    unittest.main()
