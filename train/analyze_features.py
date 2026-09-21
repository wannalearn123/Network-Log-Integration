#!/usr/bin/env python3
# Feature correlation analysis for CICIDS2017 CSVs — stdout only.
#
# Zero args, zero file writes: reads the labeled flow CSVs, prints a
# correlation report to stdout. Read-only; creates no documents.
#
# Usage: .venv/bin/python train/analyze_features.py

import csv
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"

FILES = [
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
]

REDUNDANT_R = 0.95
NOSIGNAL_R = 0.02
LEAKAGE_AUC = 0.99
TRIAGE_ROWS_PER_FILE = 10000


def iter_labeled(path):
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]
        li = header.index("Label")
        for row in reader:
            if len(row) <= li:
                continue
            yield ([c.strip() for i, c in enumerate(row) if i != li],
                   0 if row[li].strip() == "BENIGN" else 1)


def main():
    names = None
    sample = []
    for fn in FILES:
        it = iter_labeled(DATA / fn)
        if names is None:
            with open(DATA / fn, newline="") as f:
                r = csv.reader(f)
                hdr = [h.strip() for h in next(r)]
                li = hdr.index("Label")
                names = [h for i, h in enumerate(hdr) if i != li]
        for i, (feats, _) in enumerate(it):
            if i >= TRIAGE_ROWS_PER_FILE:
                break
            sample.append(feats)
    ncol = len(names)

    ok = np.zeros(ncol)
    for r in sample:
        for c, v in enumerate(r):
            try:
                float(v)
                ok[c] += 1
            except ValueError:
                pass
    ok /= len(sample)
    num_idx = [c for c in range(ncol) if ok[c] >= 0.99]
    print(f"# rows triaged: {len(sample)} | numeric cols: {len(num_idx)}/{ncol}")

    # Full streaming load, numeric columns only.
    chunks, labels, chunk = [], [], []
    n_total, n_atk = 0, 0
    for fn in FILES:
        for feats, y in iter_labeled(DATA / fn):
            vals = []
            for c in num_idx:
                try:
                    x = float(feats[c])
                except (ValueError, IndexError):
                    x = np.nan
                vals.append(x)
            chunk.append(vals)
            labels.append(y)
            n_total += 1
            n_atk += y
            if len(chunk) >= 50000:
                chunks.append(np.array(chunk, dtype=np.float64))
                chunk = []
    if chunk:
        chunks.append(np.array(chunk, dtype=np.float64))
    X = np.vstack(chunks)
    y = np.array(labels, dtype=np.int8)
    print(f"# loaded: {n_total} flows ({n_atk} attack, {n_total - n_atk} benign)")

    X[~np.isfinite(X)] = np.nan
    med = np.nanmedian(X, axis=0)
    med[~np.isfinite(med)] = 0.0
    miss = np.isnan(X)
    X[miss] = np.take(med, np.where(miss)[1])

    feat_names = [names[c] for c in num_idx]
    std = X.std(axis=0)
    keep = std > 1e-9
    X = X[:, keep]
    feat_names = [n for n, k in zip(feat_names, keep) if k]
    nf = X.shape[1]
    print(f"# after variance filter: {nf} features\n")

    from sklearn.metrics import roc_auc_score

    # Feature-feature Pearson.
    C = np.corrcoef(X, rowvar=False)
    C = np.nan_to_num(C, nan=0.0)

    # Feature-label point-biserial + single-feature AUC.
    rl, auc = np.zeros(nf), np.zeros(nf)
    yc = y.astype(np.float64)
    ys = yc.std()
    for j in range(nf):
        col = X[:, j]
        rl[j] = (np.cov(col, yc, bias=True)[0, 1] / (col.std() * ys)
                 if col.std() > 0 and ys > 0 else 0.0)
        try:
            auc[j] = roc_auc_score(y, col)
        except ValueError:
            auc[j] = 0.5

    order = np.argsort(-np.abs(rl))
    print("=" * 64)
    print("LABEL SIGNAL (point-biserial r, single-feature AUC, high -> low)")
    print("=" * 64)
    for j in order:
        print(f"  {feat_names[j]:28s} r={rl[j]:+.4f}  AUC={auc[j]:.4f}")

    print()
    print("=" * 64)
    print(f"REDUNDANT PAIRS (|r| > {REDUNDANT_R})")
    print("=" * 64)
    pairs = [(abs(C[a, b]), a, b) for a in range(nf)
             for b in range(a + 1, nf) if abs(C[a, b]) > REDUNDANT_R]
    pairs.sort(reverse=True)
    if pairs:
        for r, a, b in pairs[:100]:
            print(f"  {feat_names[a]:28s} vs {feat_names[b]:28s} r={C[a, b]:+.4f}")
        if len(pairs) > 100:
            print(f"  ... and {len(pairs) - 100} more")
    else:
        print("  (none)")
    print(f"  total redundant pairs: {len(pairs)}")

    print()
    print("=" * 64)
    print(f"NO-SIGNAL (|r_label| < {NOSIGNAL_R}) — drop candidates")
    print("=" * 64)
    quiet = [j for j in range(nf) if abs(rl[j]) < NOSIGNAL_R]
    if quiet:
        for j in sorted(quiet, key=lambda k: abs(rl[k])):
            print(f"  {feat_names[j]:28s} r={rl[j]:+.4f}  AUC={auc[j]:.4f}")
    else:
        print("  (none)")
    print(f"  total no-signal: {len(quiet)}")

    print()
    print("=" * 64)
    print(f"LEAKAGE SUSPECTS (AUC > {LEAKAGE_AUC} or < {1 - LEAKAGE_AUC}) — review only")
    print("=" * 64)
    leaks = [j for j in range(nf)
             if auc[j] > LEAKAGE_AUC or auc[j] < 1 - LEAKAGE_AUC]
    if leaks:
        for j in sorted(leaks, key=lambda k: -max(auc[k], 1 - auc[k])):
            print(f"  {feat_names[j]:28s} r={rl[j]:+.4f}  AUC={auc[j]:.4f}")
    else:
        print("  (none)")
    print(f"  total suspects: {len(leaks)}")
    sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print("note: args ignored (script takes none)", file=sys.stderr)
    main()
