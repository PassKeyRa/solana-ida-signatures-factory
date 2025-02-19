import requests
import json
import argparse

url = "https://crates.io/api/v1/crates"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("crate", help="Crate name")
    args = parser.parse_args()

    versions = []
    vs = requests.get(f"{url}/{args.crate}/versions")
    for v in vs.json()['versions']:
        if not v['yanked']:
            versions.append(v['num'])

    print("\n".join(versions))

if __name__ == "__main__":
    main()
