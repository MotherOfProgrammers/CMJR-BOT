from moderation.links import find_links


messages = [
    "Hello everyone!",
    "Check this https://example.com",
    "Visit https://google.com and https://github.com",
]


for message in messages:
    links = find_links(message)

    print(f"Message: {message}")
    print(f"Links: {links}")
    print()
