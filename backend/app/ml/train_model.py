r"""
Train the CyberGuardian URL phishing classifier on real data.

Run from the repo root:

  python -m backend.app.ml.train_model ^
      --phishing data\phishing_urls.txt --benign data\benign_urls.txt ^
      --holdout-phishing data\openphish.txt --host-only

Input files (any mix):
  - .txt            one URL per line ('#' lines are ignored)
  - .csv / .tsv     a 'url' column if there is one, otherwise the column that
                    looks most like URLs

--host-only reduces every URL to 'http://<hostname>' before training. Use it
when one class has paths or schemes the other doesn't (a common dataset flaw).
At inference time, call host_only_url() on the URL before predicting.
"""
import argparse
import json
import os
import random
import re
import shutil
from datetime import datetime, timezone
from io import StringIO
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

try:
    from backend.app.ml.feature_extractor import FEATURE_ORDER, extract_url_features, host_only_url
except ImportError:  # running from inside backend/
    from app.ml.feature_extractor import FEATURE_ORDER, extract_url_features, host_only_url

try:
    import tldextract
    # include_psl_private_domains: 'x.vercel.app' and 'y.vercel.app' are different sites
    _TLD = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:  # pragma: no cover
    _TLD = None

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), "phishing_xgb_v1.pkl")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


# --------------------------------------------------------------------------- #
# Loading and cleaning
# --------------------------------------------------------------------------- #
def registered_domain(url: str) -> str:
    try:
        host = (urlparse(url if "://" in url else "//" + url).hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    if _TLD is not None:
        try:
            return _TLD(host).registered_domain or host
        except Exception:
            pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _read_table(path: str, sep: str, header) -> pd.DataFrame:
    # Drop '#' comment lines ourselves: pandas' comment="#" would also cut URLs at '#fragments'
    with open(path, encoding="utf-8", errors="ignore") as f:
        text = "".join(line for line in f if not line.lstrip().startswith("#"))
    return pd.read_csv(StringIO(text), sep=sep, header=header, engine="python", on_bad_lines="skip")


def _http_fraction(series: pd.Series) -> float:
    s = series.dropna().astype(str).str.strip().str.lower()
    return float(s.str.startswith(("http://", "https://")).mean()) if len(s) else 0.0


def load_urls(path: str) -> list:
    if not path.lower().endswith((".csv", ".tsv")):
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]

    sep = "\t" if path.lower().endswith(".tsv") else ","
    try:
        df = _read_table(path, sep, header="infer")
        for col in df.columns:
            if str(col).strip().lower() in ("url", "domain"):
                return df[col].dropna().astype(str).str.strip().tolist()
    except Exception:
        pass

    df = _read_table(path, sep, header=None)
    fractions = [_http_fraction(df[c]) for c in df.columns]
    best = int(np.argmax(fractions))
    if fractions[best] >= 0.5:
        col = df.columns[best]
    elif df.shape[1] == 2 and pd.to_numeric(df.iloc[:, 0], errors="coerce").notna().mean() > 0.9:
        col = df.columns[1]  # "rank,domain" style lists
    else:
        col = df.columns[0]
    return df[col].dropna().astype(str).str.strip().tolist()


def load_all(paths) -> list:
    urls = []
    for p in paths or []:
        loaded = load_urls(p)
        print(f"  loaded {len(loaded):>8,} rows from {p}")
        urls.extend(loaded)
    return urls


def clean(urls) -> list:
    seen, out = set(), []
    for u in urls:
        u = u.strip().strip('"')
        if not u or len(u) > 2048:
            continue
        if not _SCHEME.match(u):
            u = "http://" + u
        key = u.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def to_hosts(urls) -> list:
    return clean([host_only_url(u) for u in urls])


def featurize(urls, label: int) -> pd.DataFrame:
    df = pd.DataFrame([extract_url_features(u) for u in urls])[FEATURE_ORDER]
    df["label"] = label
    df["group"] = [registered_domain(u) for u in urls]
    df["url"] = urls
    return df


def prep(df: pd.DataFrame, neutralize) -> pd.DataFrame:
    """Feature matrix in the exact training order. Neutralized columns are held
    constant, so the model ignores them but inference can still pass all 12."""
    X = df[FEATURE_ORDER].copy()
    for f in neutralize:
        X[f] = 0
    return X


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def shape_report(df: pd.DataFrame):
    print("\n--- Dataset shape (look for shortcuts the model could learn) ---")
    stats = {}
    for name, label in (("benign", 0), ("phishing", 1)):
        sub = df[df["label"] == label]
        stats[name] = {
            "rows": len(sub),
            "https": float(sub["https_status"].mean()),
            "has_path": float((sub["path_depth"] > 0).mean()),
            "mean_len": float(sub["url_length"].mean()),
        }
        s = stats[name]
        print(f"{name:>9}: rows={s['rows']:,}  https={s['https']:.0%}  "
              f"has_path={s['has_path']:.0%}  mean_url_length={s['mean_len']:.0f}")
    if abs(stats["benign"]["https"] - stats["phishing"]["https"]) > 0.3:
        print("WARNING: https share differs a lot between classes. The model may learn "
              "'http = phishing'. Try --host-only, or compare the 'without https_status' row below.")
    if abs(stats["benign"]["has_path"] - stats["phishing"]["has_path"]) > 0.3:
        print("WARNING: one class mostly has paths and the other doesn't. The model may learn "
              "'has path = phishing'. Use --host-only, or get benign URLs with real paths.")


def evaluate(model, X, y) -> dict:
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)
    out = {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
    }
    if len(set(y)) == 2:
        fpr, tpr, _ = roc_curve(y, proba)
        out["roc_auc"] = float(roc_auc_score(y, proba))
        out["pr_auc"] = float(average_precision_score(y, proba))
        out["recall_at_1pct_fpr"] = float(tpr[fpr <= 0.01].max())
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out["confusion"] = {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    return out


def show(title: str, m: dict):
    extra = ""
    if "roc_auc" in m:
        extra = (f"  ROC-AUC={m['roc_auc']:.3f}  PR-AUC={m['pr_auc']:.3f}  "
                 f"recall@1%FPR={m['recall_at_1pct_fpr']:.3f}")
    c = m["confusion"]
    print(f"{title:<26} acc={m['accuracy']:.3f}  P={m['precision']:.3f}  R={m['recall']:.3f}  "
          f"F1={m['f1']:.3f}{extra}  [TN={c['tn']} FP={c['fp']} FN={c['fn']} TP={c['tp']}]")


def train_xgb(train: pd.DataFrame, neutralize, seed: int) -> XGBClassifier:
    model = XGBClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_lambda=2.0,
        eval_metric="logloss",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(prep(train, neutralize), train["label"])
    return model


def holdout_report(model, neutralize, train_groups, phish_files, benign_files, host_only):
    frames = []
    for files, label in ((phish_files, 1), (benign_files, 0)):
        urls = clean(load_all(files)) if files else []
        if urls and host_only:
            urls = to_hosts(urls)
        if urls:
            frames.append(featurize(urls, label))
    if not frames:
        return
    hold = pd.concat(frames, ignore_index=True)
    before = len(hold)
    hold = hold[~hold["group"].isin(train_groups)]
    # One row per domain, so a single campaign can't dominate the result
    hold = hold.drop_duplicates(subset=["group", "label"])
    print(f"\n--- Second-source holdout ({len(hold):,} distinct domains; "
          f"{before - len(hold):,} rows removed as duplicates or shared with training data) ---")
    pred = model.predict(prep(hold, neutralize))
    for label, name, metric in ((1, "phishing", "detection rate"), (0, "benign", "false-positive rate")):
        sub = hold["label"] == label
        if sub.any():
            print(f"{name:>9}: {metric} = {float((pred[sub.values] == 1).mean()):.3f} (n={int(sub.sum()):,})")
    if hold["label"].nunique() == 2:
        show("holdout (both classes)", evaluate(model, prep(hold, neutralize), hold["label"]))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phishing", nargs="+", required=True, help="phishing URL file(s)")
    p.add_argument("--benign", nargs="+", required=True, help="benign URL file(s)")
    p.add_argument("--holdout-phishing", nargs="*", default=[], help="phishing from a DIFFERENT source, test only")
    p.add_argument("--holdout-benign", nargs="*", default=[], help="benign from a DIFFERENT source, test only")
    p.add_argument("--host-only", action="store_true",
                   help="reduce every URL to http://<hostname> (removes path and scheme shortcuts)")
    p.add_argument("--max-per-class", type=int, default=50000)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--neutralize", nargs="*", default=[], choices=FEATURE_ORDER,
                   help="features the saved model should ignore, e.g. https_status")
    p.add_argument("--out", default=DEFAULT_OUT)
    return p.parse_args()


def main():
    args = parse_args()
    rng = random.Random(args.seed)

    print("Loading data...")
    phish = clean(load_all(args.phishing))
    benign = clean(load_all(args.benign))
    print(f"After cleaning and dedup: phishing={len(phish):,}  benign={len(benign):,}")

    if args.host_only:
        phish, benign = to_hosts(phish), to_hosts(benign)
        print(f"Host-only mode, unique hosts: phishing={len(phish):,}  benign={len(benign):,}")

    if min(len(phish), len(benign)) < 500:
        raise SystemExit("Need at least a few hundred URLs per class for a meaningful result.")

    n = min(len(phish), len(benign), args.max_per_class)
    phish, benign = rng.sample(phish, n), rng.sample(benign, n)
    df = pd.concat([featurize(phish, 1), featurize(benign, 0)], ignore_index=True)
    print(f"Balanced to {n:,} per class ({len(df):,} rows)")
    shape_report(df)

    # Split by registered domain so the same site never lands in both train and test
    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed)
    tr_idx, te_idx = next(splitter.split(df, df["label"], groups=df["group"]))
    train, test = df.iloc[tr_idx], df.iloc[te_idx]
    train_groups = set(train["group"])
    print(f"\nTrain={len(train):,}  Test={len(test):,}  "
          f"domains shared between them: {len(train_groups & set(test['group']))} (should be 0)")

    print("\n--- Held-out test (grouped by domain) ---")
    variants = {"all 12 features": [], "without https_status": ["https_status"]}
    variant_metrics = {}
    for name, neutral in variants.items():
        model = train_xgb(train, neutral, args.seed)
        variant_metrics[name] = evaluate(model, prep(test, neutral), test["label"])
        show(name, variant_metrics[name])

    print("\n--- Dumb baselines: if the model barely beats these, it learned a shortcut ---")
    y_test = test["label"]
    for name, rule in (
        ("rule: http = phishing", (test["https_status"] == 0).astype(int)),
        ("rule: bad TLD or IP", ((test["suspicious_tld"] == 1) | (test["has_ip"] == 1)).astype(int)),
    ):
        print(f"{name:<26} P={precision_score(y_test, rule, zero_division=0):.3f}  "
              f"R={recall_score(y_test, rule, zero_division=0):.3f}  "
              f"F1={f1_score(y_test, rule, zero_division=0):.3f}")

    if args.holdout_phishing or args.holdout_benign:
        chosen = train_xgb(train, args.neutralize, args.seed)
        holdout_report(chosen, args.neutralize, train_groups,
                       args.holdout_phishing, args.holdout_benign, args.host_only)

    # Final model: retrain on ALL data, with the chosen neutralization
    final = train_xgb(df, args.neutralize, args.seed)
    print("\n--- Feature importance (final model) ---")
    for feat, imp in sorted(zip(FEATURE_ORDER, final.feature_importances_), key=lambda t: -t[1]):
        print(f"{feat:>16}: {imp:.3f}")

    if os.path.exists(args.out):
        shutil.copy2(args.out, args.out + ".bak")
        print(f"\nBacked up the previous model to {args.out}.bak")
    joblib.dump(final, args.out)

    reported = next(m for name, m in variant_metrics.items()
                    if (name == "without https_status") == ("https_status" in args.neutralize))
    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_order": FEATURE_ORDER,
        "neutralized_features": args.neutralize,
        "host_only": args.host_only,
        "rows_per_class": n,
        "split": "GroupShuffleSplit by registered domain",
        "grouped_test_metrics": reported,
    }
    with open(os.path.splitext(args.out)[0] + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved model to {args.out} (metrics saved next to it as .meta.json)")


if __name__ == "__main__":
    main()
