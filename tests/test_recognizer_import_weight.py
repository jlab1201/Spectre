"""Every module's recognizer must import without that module's heavy deps.

Spec: the module-selection design spec §3.2.

The design deleted a planned "shadow recognizer" subsystem (a static YAML
mirror of each recognizer's extensions/magic, for modules whose deps are
absent) on the strength of one fact: every recognizer imports only pathlib +
spectre.core.base, so the REAL recognizer is always available and shadows
would only have added false positives.

That fact is load-bearing and nothing else enforces it. If a recognizer ever
grows a heavy import, the module stops loading on a partial install, its
evidence silently triages UNRECOGNIZED ("no analyzer module claimed it" —
false, the module is installed), and the deleted fallback is not there to
catch it. Fail loudly here instead.
"""

import subprocess
import sys

from spectre.modules import registry

# Distributions that are optional or externally provided. A recognizer that
# needs any of these at import time breaks the keystone.
BLOCKED = ("volatility3", "yara", "Evtx", "pefile", "magic", "pytsk3", "pyewf")


def _module_dirs():
    return sorted(
        c.name for c in registry.MODULES_DIR.iterdir()
        if c.is_dir()
        and not c.name.startswith((".", "__"))
        and (c / "recognizer.py").exists()
    )


def test_all_modules_have_a_recognizer_module():
    """Guard the guard: if recognizers move, this test must not silently
    start checking nothing."""
    assert len(_module_dirs()) == 8, _module_dirs()


def test_every_recognizer_imports_without_heavy_deps():
    blocked = "\n".join(f"    sys.modules[{d!r}] = None" for d in BLOCKED)
    failures = []
    for name in _module_dirs():
        code = (
            "import sys\n"
            "if True:\n" + blocked + "\n"
            f"import spectre.modules.{name}.recognizer as r\n"
            "assert r.RECOGNIZERS, 'no RECOGNIZERS exported'\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append(f"{name}: {proc.stderr.strip().splitlines()[-1]}")
    assert not failures, (
        "recognizer(s) need a heavy dependency at import time, which breaks "
        "the no-shadow-recognizer design (spec §3.2):\n" + "\n".join(failures)
        + "\n\nThe failures above name the offending modules exactly. (Before "
        "stage S-B emptied src/spectre/modules/__init__.py, its eager imports "
        "meant ONE offending module failed ALL 8 — see "
        "test_dependency_truth.py::"
        "test_modules_package_does_not_eagerly_import_modules, which keeps it "
        "that way.)"
    )
