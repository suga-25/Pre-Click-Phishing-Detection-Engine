import json
import os
import requests

API_URL = "http://127.0.0.1:5000/api/analyze"
OUTPUT_FILE = "benchmark_results.json"

# ==============================================================================
# PHASE 5.2: EDGE-CASE BENCHMARK DATASET (25 ITEMS)
# ==============================================================================
EDGE_CASE_DATASET = [
    # --- LEGITIMATE EDGE CASES ---
    {
        "url": "https://github.com/login",
        "truth": "CLEAN",
        "note": "Clean major brand with login path",
    },
    {
        "url": "https://accounts.google.com/ServiceLogin?service=mail",
        "truth": "CLEAN",
        "note": "Clean multi-subdomain + login query",
    },
    {
        "url": "https://www.paypal.com/us/signin",
        "truth": "CLEAN",
        "note": "Clean financial portal",
    },
    {
        "url": "https://bit.ly/3xXyZ1",
        "truth": "SUSPICIOUS",
        "note": "Legitimate shortener usage (masking)",
    },
    {
        "url": "http://example.com/login.php",
        "truth": "CLEAN",
        "note": "Insecure HTTP on clean domain with login file",
    },
    {
        "url": "https://marketing.hubspot.com/email/verify?token=12345",
        "truth": "CLEAN",
        "note": "Legitimate SaaS marketing automation link",
    },
    {
        "url": "https://aws.amazon.com/console/billing/reports",
        "truth": "CLEAN",
        "note": "Clean enterprise cloud portal with subdomains",
    },
    {
        "url": "https://medium.com/@user/how-to-secure-your-account-1234",
        "truth": "CLEAN",
        "note": "Clean blog post title containing security keywords",
    },
    {
        "url": "https://zoom.us/j/9876543210?pwd=V1JpTXlSU0h2S1BWR",
        "truth": "CLEAN",
        "note": "Clean conference link with long query string",
    },
    {
        "url": "https://login.microsoftonline.com/common/oauth2/authorize",
        "truth": "CLEAN",
        "note": "Clean OAuth authorization endpoint",
    },
    {
        "url": "https://docs.google.com/document/d/1A2B3C4D5E/edit?usp=sharing",
        "truth": "CLEAN",
        "note": "Clean Google Docs file sharing link",
    },
    # --- ADVERSARIAL & EVASION CASES ---
    {
        "url": "https://paypal.com.account-verification-service.top/login",
        "truth": "PHISHING",
        "note": "Brand in subdomain + suspicious TLD",
    },
    {
        "url": "http://192.168.1.1/admin/login.html",
        "truth": "PHISHING",
        "note": "Raw IP host targeting local device admin",
    },
    {
        "url": "https://accounts-google-com.login-verify-security.xyz/auth",
        "truth": "PHISHING",
        "note": "Hyphenated brand spoofing in domain",
    },
    {
        "url": "https://login%20update%20billing.net/verify",
        "truth": "PHISHING",
        "note": "URL Percent encoding evasion trick",
    },
    {
        "url": "https://drop-box-share-download.site/file/view",
        "truth": "PHISHING",
        "note": "Hyphenated brand variation + .site TLD",
    },
    {
        "url": "https://wellsfargo-customer-verify.info/auth/login",
        "truth": "PHISHING",
        "note": "Brand keyword combination + .info TLD",
    },
    {
        "url": "https://chase-bank-online-banking-portal.com/login",
        "truth": "PHISHING",
        "note": "Excessive hyphenation keyword stuffing",
    },
    {
        "url": "https://raw.githubusercontent.com/user/repo/main/login.html",
        "truth": "PHISHING",
        "note": "Phishing kit hosted on public code repository",
    },
    {
        "url": "http://secure.login.update.bank.account.attacker.com/user",
        "truth": "PHISHING",
        "note": "Deep subdomain chain obfuscation over HTTP",
    },
    {
        "url": "https://appleid.apple.com.verify-identity-system.tech/login",
        "truth": "PHISHING",
        "note": "Exact brand string embedded as subdomain prefix",
    },
    {
        "url": "https://tinyurl.com/bank-account-security-update",
        "truth": "PHISHING",
        "note": "Shortened link targeting banking verification",
    },
    {
        "url": "https://office365-login-microsoft.online/auth",
        "truth": "PHISHING",
        "note": "Legitimate product combo impersonation",
    },
    {
        "url": "https://netflix-account-renew-billing.tech/user/update",
        "truth": "PHISHING",
        "note": "Subscription scam domain pattern",
    },
    {
        "url": "http://10.0.0.1/verify/paypal/account",
        "truth": "PHISHING",
        "note": "Raw internal IP + brand path spoof",
    },
]


def classify_score(score):
    """Fallback classifier based on score."""
    if score < 30:
        return "CLEAN"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "PHISHING"


def run_evaluation():
    print("=" * 80)
    print("RUNNING PHASE 5.2 / 5.3 STRESS BENCHMARK EVALUATION")
    print("=" * 80)

    tp, tn, fp, fn = 0, 0, 0, 0
    multiclass_matrix = {
        "CLEAN": {"CLEAN": 0, "SUSPICIOUS": 0, "PHISHING": 0},
        "SUSPICIOUS": {"CLEAN": 0, "SUSPICIOUS": 0, "PHISHING": 0},
        "PHISHING": {"CLEAN": 0, "SUSPICIOUS": 0, "PHISHING": 0},
    }

    results_log = []
    session = requests.Session()

    for idx, item in enumerate(EDGE_CASE_DATASET, start=1):
        url = item["url"]
        truth = item["truth"]
        note = item["note"]

        try:
            resp = session.post(
                API_URL,
                json={"url": url},
                headers={"Content-Type": "application/json"},
                timeout=5,
            )

            if resp.status_code != 200:
                print(f"[{idx:02d}] ERROR: API responded with HTTP {resp.status_code}")
                continue

            data = resp.json()
            score = data.get("risk_score", 0)
            pred_class = data.get("classification")

            if pred_class == "LOW":
                predicted_label = "CLEAN"
            elif pred_class == "MEDIUM":
                predicted_label = "SUSPICIOUS"
            elif pred_class == "HIGH":
                predicted_label = "PHISHING"
            else:
                predicted_label = (
                    pred_class
                    if pred_class in ["CLEAN", "SUSPICIOUS", "PHISHING"]
                    else classify_score(score)
                )

            is_actual_threat = truth in ["SUSPICIOUS", "PHISHING"]
            is_pred_threat = predicted_label in ["SUSPICIOUS", "PHISHING"]

            if is_actual_threat and is_pred_threat:
                res_str = "PASS (TP)"
                tp += 1
            elif not is_actual_threat and not is_pred_threat:
                res_str = "PASS (TN)"
                tn += 1
            elif not is_actual_threat and is_pred_threat:
                res_str = "FAIL (FP)"
                fp += 1
            else:
                res_str = "FAIL (FN)"
                fn += 1

            multiclass_matrix[truth][predicted_label] += 1

            print(
                f"[{idx:02d}/{len(EDGE_CASE_DATASET):02d}] "
                f"Score: {score:3d}/100 | "
                f"Truth: {truth:10s} | "
                f"Pred: {predicted_label:10s} | "
                f"Result: {res_str:9s} | "
                f"{url[:40]}"
            )

            results_log.append(
                {
                    "id": idx,
                    "url": url,
                    "truth": truth,
                    "predicted": predicted_label,
                    "score": score,
                    "result": res_str,
                    "note": note,
                    "reasons": data.get("explainable_reasons", []),
                }
            )

        except requests.exceptions.ConnectionError:
            print(f"\n[!] CONNECTION ERROR: Cannot reach API endpoint at {API_URL}.")
            print("    Ensure your Flask app is running (`python app.py`).\n")
            return
        except Exception as e:
            print(f"[{idx:02d}] ERROR: {e}")
            continue

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 80)
    print("BINARY THREAT METRICS SUMMARY (Threat vs. Non-Threat)")
    print("=" * 80)
    print(f"True Positives  (TP) : {tp:2d} | False Positives (FP) : {fp:2d}")
    print(f"True Negatives  (TN) : {tn:2d} | False Negatives (FN) : {fn:2d}")
    print("-" * 80)
    print(f"Accuracy  : {accuracy * 100:.2f}%")
    print(f"Precision : {precision * 100:.2f}%")
    print(f"Recall    : {recall * 100:.2f}%")
    print(f"F1-Score  : {f1 * 100:.2f}%")

    print("\n" + "=" * 80)
    print("3-CLASS CONFUSION MATRIX (Row = Ground Truth, Column = Predicted)")
    print("=" * 80)
    print(f"{'Actual \\ Pred':<15} | {'CLEAN':<10} | {'SUSPICIOUS':<10} | {'PHISHING':<10}")
    print("-" * 55)
    for row_label in ["CLEAN", "SUSPICIOUS", "PHISHING"]:
        c_val = multiclass_matrix[row_label]["CLEAN"]
        s_val = multiclass_matrix[row_label]["SUSPICIOUS"]
        p_val = multiclass_matrix[row_label]["PHISHING"]
        print(f"{row_label:<15} | {c_val:<10d} | {s_val:<10d} | {p_val:<10d}")
    print("=" * 80)

    failures = [r for r in results_log if "FAIL" in r["result"]]
    if failures:
        print("\n" + "!" * 80)
        print("PHASE 5.4 ERROR ANALYSIS (EDGE-CASE FAILURES)")
        print("!" * 80)
        for f in failures:
            print(f"\n[Item #{f['id']}] URL: {f['url']}")
            print(f"Type: {f['result']} | Expected: {f['truth']} | Predicted: {f['predicted']} (Score: {f['score']}/100)")
            print(f"Context Note: {f['note']}")
            print("Triggered Rules:")
            for r in f["reasons"]:
                print(f"  - {r}")
        print("!" * 80)
    else:
        print("\n[+] SUCCESS: All benchmark test cases passed perfectly!")

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "summary": {
                        "accuracy": accuracy,
                        "precision": precision,
                        "recall": recall,
                        "f1_score": f1,
                    },
                    "matrix": multiclass_matrix,
                    "details": results_log,
                },
                file,
                indent=2,
            )
        print(f"\n[+] Full results exported to '{OUTPUT_FILE}'")
    except IOError as e:
        print(f"\n[-] Failed to write results to disk: {e}")


if __name__ == "__main__":
    run_evaluation()