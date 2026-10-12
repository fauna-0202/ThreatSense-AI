"""Performance and reliability benchmark runner."""

import time
import json
from pathlib import Path
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from threatsense.storage.models import Base
from threatsense.ingestion.schemas import RawNetworkEvent
from threatsense.ingestion.normalizer import normalize_event
from threatsense.detection.engine import DetectionEngine
from threatsense.storage.repository import AlertRepository


def run_benchmarks(num_events: int = 250, reports_dir: str = "./artifacts/reports"):
    rep_dir = Path(reports_dir)
    rep_dir.mkdir(parents=True, exist_ok=True)

    engine_db = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_db)
    Session = sessionmaker(bind=engine_db)
    db = Session()

    engine = DetectionEngine()

    latencies_ms = []
    t_start_total = time.perf_counter()

    for i in range(num_events):
        raw = RawNetworkEvent(
            ts=1697040000.0 + i,
            src_ip=f"192.168.1.{(i % 200) + 1}",
            src_port=40000 + (i % 20000),
            dst_ip="10.0.0.1",
            dst_port=80 if i % 2 == 0 else 443,
            protocol="tcp",
            duration=0.25,
            orig_bytes=500 + i * 2,
            resp_bytes=2000 + i * 5,
            orig_pkts=5 + (i % 10),
            resp_pkts=10 + (i % 15),
        )
        t0 = time.perf_counter()
        ev = normalize_event(raw)
        res = engine.analyze_event(ev, db=db)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    t_end_total = time.perf_counter()
    total_time = t_end_total - t_start_total
    throughput_eps = float(num_events / total_time)

    # Benchmark database query latency
    t_q0 = time.perf_counter()
    alerts, total = AlertRepository.list_alerts(db, skip=0, limit=50)
    t_q1 = time.perf_counter()
    query_latency_ms = (t_q1 - t_q0) * 1000.0

    p50 = float(np.percentile(latencies_ms, 50))
    p95 = float(np.percentile(latencies_ms, 95))
    p99 = float(np.percentile(latencies_ms, 99))
    mean_latency = float(np.mean(latencies_ms))

    results = {
        "benchmark_workload_events": num_events,
        "total_elapsed_seconds": round(total_time, 3),
        "throughput_events_per_sec": round(throughput_eps, 2),
        "inference_latency_ms": {
            "mean": round(mean_latency, 2),
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
        },
        "database_query_latency_ms": round(query_latency_ms, 2),
    }

    report_file = rep_dir / "performance_benchmarks.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    db.close()
    print("Benchmark complete:")
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_benchmarks()
