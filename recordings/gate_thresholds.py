"""Choose the regression gate's thresholds from the dev split, and write them to examples/data/gate/thresholds.json.

No model runs here: both dev runs are replayed from their recordings, and the rule is lib/gate.py choose. The file is
written when the dev choice differs from the stored one, and the old and new values are printed; a re-run with no change
writes nothing. examples/gate-thresholds.py reads the file.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from lib import gate  # noqa: E402  (the rule and the file path; lib is imported before any numerical library)


def main():
    baseline = gate.dev_run("baseline")
    defended = gate.dev_run("enforce-args")  # the defended configuration the gate protects
    thresholds, numbers = gate.choose(defended, baseline)
    stored = {"attack_upper_max": thresholds.attack_upper_max, "utility_lower_min": thresholds.utility_lower_min}
    if gate.THRESHOLDS_FILE.exists():
        old = gate.Thresholds.load()
        if old == thresholds:
            print("thresholds.json already matches dev; nothing written")
            return
        print(f"stored before: ceiling {old.attack_upper_max:.2f}, floor {old.utility_lower_min:+.2f}")
    gate.THRESHOLDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    gate.THRESHOLDS_FILE.write_text(json.dumps(stored, sort_keys=True) + "\n", encoding="utf-8")
    print(f"thresholds.json written: ceiling {numbers['ceiling']:.2f}, floor {numbers['floor']:+.2f}")


if __name__ == "__main__":
    main()
