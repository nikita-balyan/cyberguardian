import pandas as pd

df = pd.read_csv("data/crux.csv.gz", header=None, names=["origin", "rank"])
df = df[df["origin"].astype(str).str.startswith("http")]
df["rank"] = pd.to_numeric(df["rank"], errors="coerce")
top = df[df["rank"] <= 100000]["origin"]

print(f"{len(top):,} origins. Sample:")
print("\n".join(top.sample(8, random_state=1)))

with open("data/crux_benign.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(top))