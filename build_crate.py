import os
import argparse
import pathlib
import shutil
import subprocess
import os
from colorama import Fore, Style, init

init()

SOLANA_DIR = "solana"
CRATES_DIR = "crates"

def ahash_patch(crate_dir: pathlib.Path):
    patch = "\n[dependencies]\nahash = \"=0.8.6\""
    with open(crate_dir / "Cargo.toml", "a") as f:
        f.write(patch)
    

def build_crate(crate: str, version: str, solana_version: str, only_rlib=True):
    solana_dir = pathlib.Path(SOLANA_DIR) / f"solana-release-{solana_version}"
    if not solana_dir.exists():
        print(f"{Fore.BLUE}Solana version {solana_version} not found, installing...{Style.RESET_ALL}")
        process = subprocess.Popen(f"bash install-solana.sh {solana_version}", shell=True)
        process.wait()
        if process.returncode != 0:
            print(f"{Fore.RED}Failed to install solana version {solana_version}{Style.RESET_ALL}")
            return
    
    crate_dir = pathlib.Path(CRATES_DIR) / f"{crate}-{version}"
    if not crate_dir.exists():
        print(f"{Fore.BLUE}Crate {crate} version {version} not found, fetching...{Style.RESET_ALL}")
        process = subprocess.Popen(f"bash fetch-crate.sh {crate} {version}", shell=True)
        process.wait()
        if process.returncode != 0:
            print(f"{Fore.RED}Failed to fetch crate {crate} version {version}{Style.RESET_ALL}")
            return
    #else:
    #    if pathlib.Path(crate_dir / "target").exists():
    #        shutil.rmtree(crate_dir / "target")

    cargo_build_sbf = os.path.abspath(solana_dir / "bin" / "cargo-build-sbf")

    print(f"{Fore.BLUE}Building crate {crate} version {version}...{Style.RESET_ALL}")
    rustc_env = os.environ.copy()
    rustc_env["RUSTFLAGS"] = "-C overflow-checks=on" # enable overflow checks
    retry = False
    try:
        status = subprocess.check_output(f"cd {crate_dir} && {cargo_build_sbf}", shell=True, text=True, stderr=subprocess.STDOUT, env=rustc_env)
    except subprocess.CalledProcessError as e:
        status = e.output

    if "use of unstable library feature 'build_hasher_simple_hash_one'" in status:
        print(f"{Fore.YELLOW}build_hasher_simple_hash_one error, applying ahash patch...{Style.RESET_ALL}")
        ahash_patch(crate_dir)
        retry = True
    
    if retry:
        print(f"{Fore.BLUE}Retrying build...{Style.RESET_ALL}")
        try:
            status = subprocess.check_output(f"cd {crate_dir} && {cargo_build_sbf}", shell=True, text=True, stderr=subprocess.STDOUT, env=rustc_env)
        except subprocess.CalledProcessError as e:
            status = e.output

    print(status)
    
    if "Finished release" not in status:
        print(f"{Fore.RED}Crate {crate} version {version} build failed!{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}Crate {crate} version {version} built successfully!{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--solana-version", type=str, required=True, help="Solana version")
    parser.add_argument("crate", type=str, help="Crate name")
    parser.add_argument("version", type=str, help="Crate version")
    args = parser.parse_args()

    build_crate(args.crate, args.version, args.solana_version)