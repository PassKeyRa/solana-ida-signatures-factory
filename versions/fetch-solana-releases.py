import requests
import json

STABLE_ONLY = True

url = "https://api.github.com/repos/solana-labs/solana/releases"

def is_stable(release):
    if "Mainnet" in release["name"]:
        return True
    elif "this is a stable release" in release["body"].lower():
        return True
    return False

def main():
    releases = []
    page = 1
    while True:
        response = requests.get(url, params={"per_page": 100, "page": page})
        if response.status_code != 200:
            print(f"Error fetching releases: {response.status_code}")
            break
        releases_ = response.json()
        if len(releases_) == 0:
            break
        if STABLE_ONLY:
            releases.extend([r for r in releases_ if is_stable(r)])
        else:
            releases.extend(releases_)
        page += 1

    releases = [release["tag_name"] for release in releases]
    print("\n".join(releases))

if __name__ == "__main__":
    main()