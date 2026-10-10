import glob
import pandas as pd

matches = glob.glob("data/*[Pp]hi[Uu][Ss][Ii][Ii][Ll]*.csv")
if not matches:
    raise SystemExit("Put the PhiUSIIL CSV inside the data folder first.")
path = matches[0]
print("Reading", path)

df = pd.read_csv(path, usecols=lambda c: c.strip().lower() in ("url", "label"))
df.columns = [c.strip().lower() for c in df.columns]
df = df.dropna(subset=["url"])
df["url"] = df["url"].astype(str).str.strip()

legit = df[df["label"] == 1]["url"].drop_duplicates()   # 1 = legitimate
phish = df[df["label"] == 0]["url"].drop_duplicates()   # 0 = phishing

with open("data/benign_urls.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(legit))
with open("data/phishing_urls.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(phish))

print(f"benign: {len(legit):,}   phishing: {len(phish):,}")
print("\nSample benign:")
print("\n".join(legit.head(5)))
print("\nSample phishing:")
print("\n".join(phish.head(5)))