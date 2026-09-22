from moderation.rules import classify_domain


domains = [
    "google.com",
    "github.com",
    "example.com",
    "unknown-site.com",
]


for domain in domains:
    result = classify_domain(domain)
    print(f"{domain} -> {result}")
