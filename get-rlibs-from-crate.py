import shutil
import argparse
import subprocess
import pathlib
from colorama import Fore, Style, init
from build_crate import build_crate

init()

DEFAULT_SOLANA_VERSION = "1.18.26"
SOLANA_DIR = "solana"
CRATES_DIR = "crates"
RLIBS_DIR = "rlibs"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--solana-version", default=DEFAULT_SOLANA_VERSION, help="The Solana version used to build the crate (all except solana-program)")
    parser.add_argument("--crate", required=True, help="The crate to get the rlib from")
    parser.add_argument("--versions-file", help="The file containing the versions to get the rlib from")
    parser.add_argument("--version", help="The version to get the rlib from")
    args = parser.parse_args()

    versions = []
    if args.versions_file:
        with open(args.versions_file, "r") as f:
            for line in f:
                l = line.strip()
                if l.startswith("v"):
                    versions.append(l[1:])
                else:
                    versions.append(l)
    elif args.version:
        versions = [args.version]
    else:
        raise ValueError("Either --versions-file or --version must be provided")
    
    solana_version = args.solana_version
    crate = args.crate

    print(f"{Fore.BLUE}Getting rlibs for {crate} from {len(versions)} versions{Style.RESET_ALL}")
    for version in versions:
        version = version.strip()
        try:
            if crate == "solana-program":
                print(f"{Fore.BLUE}Getting rlib for {crate}:{version}{Style.RESET_ALL} with solana version {version}")
                build_crate(crate, version, version, only_rlib=True)
            else:
                print(f"{Fore.BLUE}Getting rlib for {crate}:{version}{Style.RESET_ALL} with solana version {solana_version}")
                build_crate(crate, version, solana_version, only_rlib=True)
        except KeyboardInterrupt:
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Error building {crate}:{version} with solana version {solana_version}: {e}{Style.RESET_ALL}")
            continue
        
        rlib_path = pathlib.Path(CRATES_DIR) / f"{crate}-{version}" / "target" / "sbf-solana-solana" / "release" / f"lib{crate.replace('-', '_')}.rlib"
        
        if not rlib_path.exists():
            print(f"{Fore.RED}Rlib for {crate}:{version} not found!{Style.RESET_ALL}")
            continue

        target_path = pathlib.Path(RLIBS_DIR) / crate / f"{crate.replace('-', '_')}-{version}.rlib"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(rlib_path, target_path)
        print(f"{Fore.GREEN}Rlib for {crate}:{version} saved to {target_path}{Style.RESET_ALL}")

        if (pathlib.Path(CRATES_DIR) / f"{crate}-{version}" / "target").exists():
            shutil.rmtree(pathlib.Path(CRATES_DIR) / f"{crate}-{version}" / "target")

        process = subprocess.Popen(f"bash remove-solana.sh {version}", shell=True)
        process.wait()

if __name__ == "__main__":
    main()
