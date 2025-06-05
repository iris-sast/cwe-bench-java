import os
import argparse
import csv
import subprocess
import json

CWE_BENCH_JAVA_ROOT_DIR = os.path.abspath(os.path.join(__file__, "..", ".."))
JAVA_ENV_DIR = os.path.join(CWE_BENCH_JAVA_ROOT_DIR, "java-env")

GRADLE_VERSIONS = json.load(open(f"{CWE_BENCH_JAVA_ROOT_DIR}/scripts/gradle_version.json"))
JDK_VERSIONS = json.load(open(f"{CWE_BENCH_JAVA_ROOT_DIR}/scripts/jdk_version.json"))

def download_gradle(version, info):
  print(f">> [CWE-Bench-Java/setup_gradle] Fetching Gradle {version}...")
  if os.path.exists(f"{JAVA_ENV_DIR}/{info['dir']}"):
    print(f">> [CWE-Bench-Java/setup_gradle] Gradle version {version} found; skipping")
  else:
    subprocess.run(["wget", info["url"]], cwd=JAVA_ENV_DIR)

    print(f">> [CWE-Bench-Java/setup_gradle] Unzipping Gradle Binary {version}...")
    subprocess.run(["unzip", "-n", info["zip_file"]], cwd=JAVA_ENV_DIR)

    print(f">> [CWE-Bench-Java/setup_gradle] Removing Downloaded File...")
    subprocess.run(["rm", info["zip_file"]], cwd=JAVA_ENV_DIR)

  print(f">> [CWE-Bench-Java/setup_gradle] Testing Downloaded Binary...")
  
  # Use JDK 8 as default for testing Gradle
  default_jdk = "8u202"
  java_home = f"{JAVA_ENV_DIR}/{JDK_VERSIONS[default_jdk]['dir']}"
  
  output = subprocess.run(
    ["gradle", "--help"],
    cwd=JAVA_ENV_DIR,
    env={
      "PATH": f"{os.environ['PATH']}:{JAVA_ENV_DIR}/{info['dir']}/bin",
      "JAVA_HOME": java_home
    },
    capture_output=True)

  if output.returncode == 0:
    print(f">> [CWE-Bench-Java/setup_gradle] Gradle version {version} successfully installed")
  else:
    print(f">> [CWE-Bench-Java/setup_gradle] Gradle version {version} installation failed:")
    print(output.stderr.decode("utf-8"))

if __name__ == "__main__":
  for (version, gradle_info) in GRADLE_VERSIONS.items():
    download_gradle(version, gradle_info)
