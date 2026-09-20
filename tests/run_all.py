"""Runs every test script in this folder and fails if any of them fails."""
import glob
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
failed = []
for path in sorted(glob.glob(os.path.join(here, "test_*.py"))):
    name = os.path.basename(path)
    print(f"=== {name}", flush=True)
    result = subprocess.run([sys.executable, "-u", path], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    passed = sum(1 for line in lines if line.startswith("PASS"))
    for line in lines:
        if line.startswith("FAIL") or line.startswith("ALL PASSED") or line.startswith("FAILED"):
            print("  " + line)
    if result.returncode != 0:
        failed.append(name)
        print(result.stderr[-2000:])
    print(f"  {passed} checks passed", flush=True)
if failed:
    print("FAILED:", ", ".join(failed))
    sys.exit(1)
print("ALL TEST FILES PASSED")
