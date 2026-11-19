"""Private -I -B child for the verified installed synthetic producer."""

import base64
import json
from pathlib import Path
import runpy
import sys


def check_origins(site):
    for name, module in tuple(sys.modules.items()):
        if name == "model_intelligence" or name.startswith("model_intelligence."):
            origin = getattr(module, "__file__", None)
            if not isinstance(origin, str) or not Path(origin).resolve().is_relative_to(site / "model_intelligence"):
                raise RuntimeError("MI module imported outside verified installation")


def main():
    site, root = map(Path, sys.argv[1:])
    if any(not Path(path).is_absolute() for path in sys.path) or str(site) not in sys.path:
        raise RuntimeError("untrusted import path")
    fixture = runpy.run_path(str(Path(__file__).with_name("mi_publication_fixture.py")))
    output = {}
    for kind in ("fresh", "stale", "withdrawn", "incompatible"):
        directory = root / kind
        directory.mkdir()
        digest = fixture["EXPECTED_SHA256"] if kind == "fresh" else fixture["VARIANT_SHA256"][kind]
        trust = fixture["publish_fixture"](directory, publication_path="/run/foundry/mi/publication.json", kind=kind)
        output[kind] = {"publication": base64.b64encode((directory / (digest + ".json")).read_bytes()).decode(),
                        "trust": trust}
    check_origins(site)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
