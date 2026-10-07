"""
Command-Line Demonstration & Execution Interface for DNSGuard Detection Engine.

Usage:
    # 1. Train and save the Isolation Forest machine learning anomaly model
    python -m detection.cli --train

    # 2. Run threat detection across all PENDING events in SQLite database
    python -m detection.cli --run

    # 3. Evaluate detection performance against benchmark dataset
    python -m detection.cli --evaluate

    # 4. Perform ad-hoc threat analysis on any domain
    python -m detection.cli --inspect zk49wlmpt982xv.info

    # 5. Display detection results summary from SQLite
    python -m detection.cli --stats
"""

import argparse
import json
from typing import Optional

from backend.logging_config import setup_logging, get_logger
from database.connection import initialize_database
from database.repository import DNSRepository
from dns_engine.sample_data import generate_sample_dataset
from detection.engine import ThreatDetectionEngine
from detection.evaluator import evaluate_detector_on_samples

logger = get_logger("detection_cli")


def cmd_train(contamination: float, model_path: Optional[str]) -> None:
    print("\n[+] Training Machine Learning Anomaly Detector (Isolation Forest)...")
    engine = ThreatDetectionEngine()
    samples = generate_sample_dataset()

    # Train only on benign baseline samples to prevent data leakage
    benign_samples = [s for s in samples if "benign" in str(s.get("synthetic_label", ""))]
    from dns_engine.features import extract_features

    training_features = []
    for s in benign_samples:
        _, details = extract_features(
            domain=s["domain"],
            query_type=s["query_type"],
            response_code=s.get("response_code", "NOERROR"),
            response_data=s.get("response_data", []),
            ttl=s.get("ttl", 300),
            packet_length=s.get("packet_length", 64),
        )
        training_features.append(details)

    summary = engine.anomaly_detector.fit(training_features, contamination=contamination)
    saved_path = engine.anomaly_detector.save(path=model_path)

    print(f"    [OK] Samples Used:   {summary['sample_count']}")
    print(f"    [OK] Contamination:  {summary['contamination']}")
    print(f"    [OK] Model Saved:    {saved_path}")
    print("[+] Model training complete and persisted successfully.\n")


def cmd_run(batch_size: int) -> None:
    print(f"\n[+] Running threat detection engine on PENDING database events (batch={batch_size})...")
    engine = ThreatDetectionEngine()
    verdicts = engine.process_pending_events(batch_size=batch_size)

    suspicious_count = sum(1 for v in verdicts if v.is_suspicious)
    clean_count = len(verdicts) - suspicious_count

    print(f"    [OK] Processed Events: {len(verdicts)}")
    print(f"    [OK] Flagged Threats:  {suspicious_count}")
    print(f"    [OK] Clean/Benign:     {clean_count}")

    if suspicious_count > 0:
        print("\n    Sample Detections:")
        for v in verdicts:
            if v.is_suspicious:
                print(f"      [!] {v.primary_threat_type.value:<10} | {v.domain} (Score: {v.overall_score}/100, Conf: {v.confidence})")
                print(f"          Reason: {v.explanation}")
    print("[+] Detection execution complete. Results saved in SQLite.\n")


def cmd_evaluate() -> None:
    print("\n[+] Evaluating Threat Detection Engine against labeled benchmark dataset...")
    engine = ThreatDetectionEngine()
    samples = generate_sample_dataset()

    report = evaluate_detector_on_samples(engine, samples, dataset_name="DNSGuard Synthetic Benchmark v1")

    print("\n=======================================================")
    print(f"  BENCHMARK EVALUATION REPORT: {report.dataset_name}")
    print("=======================================================")
    print(f"  Total Evaluated Samples:  {report.total_samples}")
    print(f"  Accuracy:                 {report.accuracy * 100:.2f}%")
    print(f"  Precision:                {report.precision * 100:.2f}%")
    print(f"  Recall:                   {report.recall * 100:.2f}%")
    print(f"  F1-Score:                 {report.f1_score:.4f}")
    print(f"  Confusion Matrix:         [[TN={report.true_negatives}, FP={report.false_positives}], [FN={report.false_negatives}, TP={report.true_positives}]]")
    print("\n  Per-Threat Category Breakdown:")
    for threat, counts in report.per_threat_breakdown.items():
        if threat == "BENIGN":
            print(f"    - {threat:<10}: Total={counts['total']}, Clean={counts.get('clean', 0)}, FalsePositives={counts.get('false_positive', 0)}")
        else:
            print(f"    - {threat:<10}: Total={counts['total']}, Detected={counts.get('detected', 0)}")

    print(f"\n  [*] Note: {report.disclaimer}\n")


def cmd_inspect(domain: str, query_type: str) -> None:
    print(f"\n[+] Executing complete threat inspection for: '{domain}' (Type: {query_type})...")
    engine = ThreatDetectionEngine()
    verdict = engine.analyze_domain(domain=domain, query_type=query_type)

    print("\n--- Consolidated Detection Assessment ---")
    print(f"  Status:             {'[!] SUSPICIOUS / THREAT' if verdict.is_suspicious else '[OK] CLEAN / BENIGN'}")
    print(f"  Primary Category:   {verdict.primary_threat_type.value}")
    if verdict.secondary_threat_types:
        print(f"  Secondary Signals:  {', '.join(t.value for t in verdict.secondary_threat_types)}")
    print(f"  Overall Score:      {verdict.overall_score}/100")
    print(f"  Confidence:         {verdict.confidence}")
    print(f"  Detection Methods:  {', '.join(verdict.detection_methods)}")
    print(f"  Explanation:        {verdict.explanation}")

    print("\n--- Individual Detector Breakdown ---")
    for name, ind_verdict in verdict.individual_verdicts.items():
        flag = "[!]" if ind_verdict.is_suspicious else "[OK]"
        print(f"  {flag} {name:<12}: Score={ind_verdict.score:<5.1f} | Conf={ind_verdict.confidence:<4.2f} | {ind_verdict.reason}")
    print("")


def cmd_stats() -> None:
    print("\n[+] Querying SQLite detection results summary...")
    repo = DNSRepository()
    suspicious = repo.list_detection_results(limit=500, suspicious_only=True)
    all_results = repo.list_detection_results(limit=500, suspicious_only=False)

    print(f"    Total Recorded Verdicts:   {len(all_results)}")
    print(f"    Suspicious Verdicts:       {len(suspicious)}")

    if suspicious:
        threat_tallies = {}
        for r in suspicious:
            t = r.detection_type.value
            threat_tallies[t] = threat_tallies.get(t, 0) + 1

        print("    Threat Category Breakdown:")
        for t, cnt in sorted(threat_tallies.items()):
            print(f"      - {t:<12}: {cnt}")
    print("")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNSGuard Detection Engine CLI: Threat detection, ML anomaly training, and benchmark evaluation."
    )
    parser.add_argument("--train", action="store_true", help="Train Isolation Forest anomaly model on baseline data")
    parser.add_argument("--contamination", type=float, default=0.10, help="Expected anomaly proportion (default: 0.10)")
    parser.add_argument("--model-path", type=str, default=None, help="Destination path for trained model")
    parser.add_argument("--run", action="store_true", help="Run detection on all PENDING SQLite events")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for event processing")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate engine on synthetic benchmark dataset")
    parser.add_argument("--inspect", type=str, help="Perform multi-detector threat analysis on a domain")
    parser.add_argument("--query-type", type=str, default="A", help="Query type for domain inspection (default: A)")
    parser.add_argument("--stats", action="store_true", help="Display SQLite detection results telemetry")

    args = parser.parse_args()

    setup_logging(log_level="INFO")
    initialize_database()

    if args.train:
        cmd_train(contamination=args.contamination, model_path=args.model_path)
    elif args.run:
        cmd_run(batch_size=args.batch_size)
    elif args.evaluate:
        cmd_evaluate()
    elif args.inspect:
        cmd_inspect(domain=args.inspect, query_type=args.query_type)
    elif args.stats:
        cmd_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
