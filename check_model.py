from backend.app.ml.feature_extractor import host_only_url
from backend.app.ml.inference import predict_phishing_probability as p

LEGIT = [
    "https://github.com/login",
    "https://docs.python.org/3/library/os.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.in/gp/help/customer/display.html?nodeId=201909000",
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://web.whatsapp.com/",
    "https://www.onlinesbi.sbi/",
]
PHISH = [
    "https://secure-paypal-login.com/verify",
    "https://login.webwindos-whatsapp.com.cn/",
    "https://www.roblox.com.mu/users/6128029595/profile",
    "http://paypal-login.vercel.app/",
    "https://trezor--brioge--help.gitbook.io/",
    "http://paypal-security-update.suspicious-domain.com/login",
]

print(f"{'raw':>6} {'host-only':>9}  url")
for title, urls in (("legit (want LOW)", LEGIT), ("phishing (want HIGH)", PHISH)):
    print(f"\n{title}")
    for u in urls:
        print(f"{p(u):6.3f} {p(host_only_url(u)):9.3f}  {u}")