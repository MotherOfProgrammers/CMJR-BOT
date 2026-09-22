from moderation.links import find_links, extract_domain


message = "Check https://example.com and https://github.com/test"

links = find_links(message)

for link in links:
    print(f"URL: {link}")
    print(f"Domain: {extract_domain(link)}")
