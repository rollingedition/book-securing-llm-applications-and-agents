"""Each isolation design on the dev split as one point, attack success against utility, with 95% bootstrap intervals in both directions.
The prose rests on the printed rates and intervals, which are the same numbers the points are drawn from."""
from lib import cases, replay, report, runs, scorers, stats  # lib first: threads and seeds are fixed here
from lib.figures import ACCENT, INK, new_figure, save

DESIGNS = ["design-dual-llm", "design-plan-then-execute", "design-taint"]  # sorted, as isolation-paired prints them
# Each label: its offset in points from the point, and its alignment, placed clear of the other points' bars.
LABEL_AT = {"baseline": (38, 0, "left", "center"), "design-dual-llm": (4, -8, "left", "top"), "design-plan-then-execute": (30, 0, "left", "center"), "design-taint": (30, 0, "left", "center")}


def scores(name, tasks, attacks):
    """Utility per benign task and attack success per case, in ID order, for the baseline or one design on dev."""
    rec = f"{name}-dev"  # the baseline's recording is baseline-dev, and each design's is design-*-dev
    model = replay.ReplayModel(rec)  # one model per recording: it reads its file once
    variant = None if name == "baseline" else name  # None replays the undefended prompt, a design names its own
    benign = runs.replay_tasks(rec, tasks, variant=variant, model=model)
    attack = runs.replay_cases(rec, attacks, variant=variant, model=model)
    return ([scorers.utility(t, benign[t.id]) for t in tasks],
            [scorers.attack_success(c, attack[c.id]) for c in attacks])


def interval(flags):
    """The 95% bootstrap interval of the rate of `flags`, in points."""
    lo, hi = stats.bootstrap_mean([1.0 if flag else 0.0 for flag in flags])  # one 0 or 1 per item
    return 100 * lo, 100 * hi


def main():
    tasks, attacks = cases.load_tasks("dev"), cases.load_cases("dev")  # 15 benign tasks, 60 attack cases
    assert (len(tasks), len(attacks)) == (15, 60)  # the counts the prose names
    fig, ax = new_figure(height=3.4)
    for name in ["baseline"] + DESIGNS:
        utility, success = scores(name, tasks, attacks)
        if name == "baseline":  # the labels isolation-paired prints for the undefended run
            report.rate_lines("baseline utility, 15 benign tasks", utility)
            report.rate_lines("baseline attack success, 60 cases", success)
        else:
            report.rate_lines(f"utility, {name}, 15 benign tasks", utility)
            report.rate_lines(f"attack success, {name}, 60 cases", success)
        x, y = 100 * sum(success) / len(success), 100 * sum(utility) / len(utility)  # attack success, utility
        (x_lo, x_hi), (y_lo, y_hi) = interval(success), interval(utility)
        color = INK if name == "baseline" else ACCENT  # the undefended run in ink, each design in the accent
        ax.errorbar(x, y, xerr=[[x - x_lo], [x_hi - x]], yerr=[[y - y_lo], [y_hi - y]], fmt="o", color=color,
                    markersize=4, capsize=2, elinewidth=1)
        dx, dy, ha, va = LABEL_AT[name]
        ax.annotate(name, (x, y), xytext=(dx, dy), textcoords="offset points", color=color, ha=ha, va=va)
    ax.set(xlim=(0, 100), ylim=(0, 100), xlabel="attack success on 60 dev cases, %", ylabel="utility on 15 dev benign tasks, %")
    save(fig, "isolation-tradeoff")


if __name__ == "__main__":
    main()
