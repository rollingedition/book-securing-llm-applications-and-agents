"""Draw each prompt defence's dev attack success against its dev utility, with the undefended baseline and 95% bootstrap intervals.
The lines name each run's attack success and utility with their counts, which the prose rests on.
"""
from lib import cases, runs, scorers, stats  # lib first: threads and seeds are fixed here
from lib.figures import ACCENT, INK, new_figure, save

DEFENCES = ("prompt-warning", "prompt-delimiters", "prompt-datamark", "prompt-encode", "prompt-repeat")
# Each label's place in data units, in empty space beside its point. The warning's point is the baseline's, so one label names both.
LABELS = {"baseline": (15.5, 88.0, "baseline and warning"), "prompt-delimiters": (1.5, 101.0, "prompt-delimiters"),
          "prompt-datamark": (6.5, 76.0, "prompt-datamark"), "prompt-encode": (1.2, 57.0, "prompt-encode"),
          "prompt-repeat": (8.5, 12.0, "prompt-repeat")}
# Delimiters has the baseline's utility, so its bars would lie on the baseline's. It is drawn 1.5 points higher, point and
# bars together, so both show and its label reaches it without crossing the baseline's bar; the printed values are unshifted.
NUDGE = {"prompt-delimiters": 1.5}


def run_dev(recording, variant=None):
    """Utility of the 15 dev benign tasks and attack success of the 60 dev cases, in ID order, as 1s and 0s."""
    benign, attacks = cases.load_tasks("dev"), cases.load_cases("dev")
    assert (len(benign), len(attacks)) == (15, 60), "the dev split has changed"  # the counts the prose names
    traces = runs.replay_tasks(recording, benign, variant=variant)
    case_traces = runs.replay_cases(recording, attacks, variant=variant)
    utility = [float(scorers.utility(t, traces[t.id])) for t in sorted(benign, key=lambda t: t.id)]
    success = [float(scorers.attack_success(c, case_traces[c.id])) for c in sorted(attacks, key=lambda c: c.id)]
    return utility, success


def rate(label, flags):
    """Print a rate with its counts and bootstrap interval, as the paired example does; return it in points, with the interval."""
    lo, hi = stats.bootstrap_mean(flags)  # the same interval the paired example prints, from the same seed
    print(f"{label}: {stats.pct(int(sum(flags)), len(flags))}")
    print(f"{label}, interval: {stats.interval_pct(lo, hi)}")
    return 100 * sum(flags) / len(flags), 100 * lo, 100 * hi


def main():
    fig, ax = new_figure(height=3.8)
    rates = {}  # each run's rates as drawn, so the warning can be checked against the baseline
    for name in DEFENCES + ("baseline",):  # the baseline last, so its ink bars sit on the warning's identical ones
        recording, variant = ("baseline-dev", None) if name == "baseline" else (f"{name}-dev", name)
        utility, success = run_dev(recording, variant)
        x, y = rate(f"{name}, attack success, 60 dev cases", success), rate(f"{name}, utility, 15 dev benign tasks", utility)
        rates[name] = (x[0], y[0])
        color = INK if name == "baseline" else ACCENT  # the baseline in ink, each defence in the accent
        ring = 9 if name == "prompt-warning" else 5  # the warning sits on the baseline's point, so its ring shows around it
        yn = y[0] + NUDGE.get(name, 0.0)  # where the run is drawn; its interval moves with it
        ax.errorbar(x[0], yn, xerr=[[x[0] - x[1]], [x[2] - x[0]]], yerr=[[y[0] - y[1]], [y[2] - y[0]]], fmt="o",
                    color=color, markersize=ring, markerfacecolor="none" if ring > 5 else color, capsize=2,
                    elinewidth=0.9, zorder=3 if name == "baseline" else 2)
        if name in LABELS:  # the warning has no label of its own: the baseline's label says it coincides
            lx, ly, text = LABELS[name]
            ax.annotate(text, (x[0], yn), xytext=(lx, ly), ha="left", va="center", color=color,
                        arrowprops=dict(arrowstyle="-", color=INK, linewidth=0.5, shrinkA=4, shrinkB=2))
    assert rates["prompt-warning"] == rates["baseline"], "the warning's point is the baseline's"  # the prose says so
    ax.set(xlabel="attack success, percent of 60 dev cases", ylabel="utility, percent of 15 dev benign tasks",
           xlim=(-1, 25), ylim=(0, 105))
    save(fig, "prompt-defence-tradeoff")


if __name__ == "__main__":
    main()
