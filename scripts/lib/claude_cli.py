"""Shared Claude CLI helper for all EpiGraph Python scripts.

Uses the claude CLI with OAuth (Max subscription). Never use the Anthropic SDK
directly -- OAuth was painful to set up and is prepaid.

Pattern: remove CLAUDECODE + ANTHROPIC_API_KEY from env, use --output-format json,
parse the {"type":"result","result":"..."} envelope.
"""

import asyncio
import json
import os
import re
import shutil


async def claude_cli_call(prompt: str, timeout_secs: int = 90, model: str | None = None) -> str:
    """Call claude CLI and return the result text.

    Raises RuntimeError if claude is not found or the call fails/times out.
    """
    claude_bin = shutil.which("claude")
    if not claude_bin:
        raise RuntimeError("claude CLI not found on PATH")

    cmd = [claude_bin, "-p", "--output-format", "json", "--max-turns", "1"]
    if model:
        cmd.extend(["--model", model])

    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDECODE", "ANTHROPIC_API_KEY")}

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=prompt.encode()),
        timeout=timeout_secs,
    )

    output = stdout.decode().strip() or stderr.decode().strip()
    if not output:
        raise RuntimeError(f"claude CLI produced no output (exit {proc.returncode})")

    envelope = json.loads(output)
    if envelope.get("is_error"):
        raise RuntimeError(f"claude CLI error: {envelope.get('result', 'unknown')}")

    result_text = envelope.get("result", "")
    # Strip markdown fences if present
    if result_text.startswith("```"):
        result_text = re.sub(r"^```(?:json)?\n?", "", result_text)
        result_text = re.sub(r"\n?```$", "", result_text)

    return result_text.strip()
