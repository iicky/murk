"""Shared fixtures for murk Python SDK tests."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def vault_dir():
    """Create a temp directory with an initialized murk vault and secrets."""
    murk_bin = Path(__file__).resolve().parents[2] / "target" / "release" / "murk"
    if not murk_bin.exists():
        pytest.skip("murk binary not found — run cargo build --release first")

    with tempfile.TemporaryDirectory() as tmpdir:
        env = {**os.environ, "PATH": f"{murk_bin.parent}:{os.environ['PATH']}"}

        # Remove any existing MURK_KEY/MURK_KEY_FILE to avoid interference.
        env.pop("MURK_KEY", None)
        env.pop("MURK_KEY_FILE", None)

        # Init vault.
        subprocess.run(
            [str(murk_bin), "init", "--vault", ".murk"],
            input="testuser\n",
            capture_output=True,
            text=True,
            cwd=tmpdir,
            env=env,
            check=True,
        )

        # Read the key from .env.
        dot_env = Path(tmpdir) / ".env"
        for line in dot_env.read_text().splitlines():
            if line.startswith("export MURK_KEY_FILE="):
                key_file = line.split("=", 1)[1].strip()
                murk_key = Path(key_file).read_text().strip()
                break
            elif line.startswith("export MURK_KEY="):
                murk_key = line.split("=", 1)[1].strip()
                break
        else:
            pytest.fail("Could not find MURK_KEY in .env")

        env["MURK_KEY"] = murk_key

        # Add secrets.
        for key, value in [
            ("DATABASE_URL", "postgres://localhost/mydb"),
            ("API_KEY", "sk-test-123"),
            ("STRIPE_SECRET", "sk_live_abc"),
        ]:
            subprocess.run(
                [str(murk_bin), "add", key, "--vault", ".murk"],
                input=f"{value}\n",
                capture_output=True,
                text=True,
                cwd=tmpdir,
                env=env,
                check=True,
            )

        yield {"path": tmpdir, "key": murk_key}
