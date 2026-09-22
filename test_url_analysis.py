from moderation.links import analyze_url


urls = [
    "https://google.com",
    "https://bit.ly/example",
    "https://192.168.1.100/login",
    "https://this-is-a-very-long-domain-name-that-we-are-testing.com",
]


for url in urls:
    print(analyze_url(url))
