"""Statement archive packaging."""

import subprocess


def pack(target: str) -> None:
    # deadbolt-expect DB-INJ-002:high
    subprocess.run(f"tar czf {target}.tgz {target}", shell=True)
