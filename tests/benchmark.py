"""Reproducible synthetic masking/SSE measurements; no network or cloud key."""

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anonymize import anonymize, load_rules, restore
from veil_protocol import SSEProcessor, json_bytes


def main():
    rules = load_rules()
    measurements = []
    for size in (1024, 10240, 102400):
        line = "ordinary document text test@example.com; card 4111 1111 1111 1111; password=synthetic\n"
        source = (line * (size // len(line) + 1))[:size] + "\n"
        elapsed = []
        for _ in range(7):
            start = time.perf_counter()
            masked, mapping, count, _ = anonymize(source, rules, auto=True)
            elapsed.append((time.perf_counter() - start) * 1000)
            assert restore(masked, mapping) == source
            assert "test@example.com" not in masked
        measurements.append({"characters": len(source), "replacements": count, "median_ms": round(statistics.median(elapsed), 3), "max_ms": round(max(elapsed), 3)})
    token = "{{VEIL_benchmark_EMAIL_1}}"
    processor = SSEProcessor("/v1/chat/completions", {token: "test@example.com"})
    frames = [b"data: " + json_bytes({"choices": [{"index": 0, "delta": {"content": char}}]}) + b"\n\n" for char in ("hello " + token + " ") * 100]
    start = time.perf_counter()
    output = b"".join(processor.process(frame) for frame in frames)
    processor.finish()
    duration = time.perf_counter() - start
    assert output.count(b"test@example.com") == 100
    report = {"masking": measurements, "sse": {"frames": len(frames), "total_ms": round(duration * 1000, 3), "frames_per_second": round(len(frames) / duration)}}
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
