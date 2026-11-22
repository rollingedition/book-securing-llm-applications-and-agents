"""Rates and intervals for the examples: printed rates with their counts, and a percentile bootstrap over items.

Each interval makes its own numpy generator from SEED, so two calls with the same data give the same interval
whatever ran before. Rates print as a percentage with one decimal and the counts beside them.
"""
from __future__ import annotations

import numpy as np

from lib import SEED

RESAMPLES = 2000  # fixed for every interval in the book


def pct(num: int, den: int) -> str:
    """A rate as printed in the book, such as `65.0% (13 of 20)`. A zero denominator is an error, not a rate."""
    if den <= 0:
        raise ValueError("a rate needs a denominator above 0")
    return f"{100 * num / den:.1f}% ({num} of {den})"


def interval_pct(lo: float, hi: float) -> str:
    """An interval of rates, rounded the same way as the rates it brackets: `[45.0%, 85.0%]`."""
    return f"[{100 * lo:.1f}%, {100 * hi:.1f}%]"


def interval_points(lo: float, hi: float) -> str:
    """An interval of differences between two rates, in percentage points with a sign: `[-4.0, +12.0] points`."""
    return f"[{100 * lo:+.1f}, {100 * hi:+.1f}] points"


def bootstrap_mean(values, level: float = 0.95, seed: int = SEED) -> tuple[float, float]:
    """The percentile bootstrap interval of the mean of `values`, resampling its entries (items) RESAMPLES times.

    `level` is 0.95 for one comparison; a chapter with m comparisons passes 1 - 0.05 / m (Bonferroni).
    """
    data = np.asarray(values, dtype=float)
    if data.ndim != 1 or data.size == 0:
        raise ValueError("a bootstrap needs a non-empty one-dimensional list of values")
    rng = np.random.default_rng(seed)  # the seed is SEED, the book's one seed
    picks = rng.integers(0, data.size, size=(RESAMPLES, data.size))
    means = data[picks].mean(axis=1)
    tail = (1.0 - level) / 2.0
    lo, hi = np.quantile(means, [tail, 1.0 - tail])
    return float(lo), float(hi)


def bootstrap_difference(first, second, level: float = 0.95, seed: int = SEED) -> tuple[float, float]:
    """The percentile bootstrap interval of mean(second) minus mean(first) for two independent groups of items.

    Each group is resampled on its own RESAMPLES times, from one generator made from `seed`, as bootstrap_mean does.
    """
    a = np.asarray(first, dtype=float)
    b = np.asarray(second, dtype=float)
    if a.ndim != 1 or b.ndim != 1 or a.size == 0 or b.size == 0:
        raise ValueError("a bootstrap difference needs two non-empty one-dimensional lists of values")
    rng = np.random.default_rng(seed)
    first_picks = rng.integers(0, a.size, size=(RESAMPLES, a.size))
    second_picks = rng.integers(0, b.size, size=(RESAMPLES, b.size))
    gaps = b[second_picks].mean(axis=1) - a[first_picks].mean(axis=1)
    tail = (1.0 - level) / 2.0
    lo, hi = np.quantile(gaps, [tail, 1.0 - tail])
    return float(lo), float(hi)


def paired_differences(before, after) -> list[float]:
    """The per-item difference after - before, for two lists over the same items in the same order.

    The paired comparison is bootstrapped over these differences with bootstrap_mean, so each item counts once.
    """
    a = [float(x) for x in before]
    b = [float(x) for x in after]
    if len(a) != len(b) or not a:
        raise ValueError("a paired comparison needs two non-empty lists of the same length, in the same item order")
    return [y - x for x, y in zip(a, b)]


