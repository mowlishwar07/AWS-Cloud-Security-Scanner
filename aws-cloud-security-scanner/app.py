import os
import io
import csv
import json
from flask import Flask, render_template, request, jsonify, Response
from botocore.exceptions import ClientError, BotoCoreError

import scanner

app = Flask(__name__)

# In-memory storage for the latest scan results for report export
latest_scan = {
    "results": None
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_environment():
    data = request.get_json() or {}
    region = data.get("region", "ap-south-1").strip() or "ap-south-1"

    try:
        results = scanner.run_scan(region=region)
        latest_scan["results"] = results
        return jsonify({"success": True, "data": results})

    except (RuntimeError, ClientError, BotoCoreError) as err:
        return jsonify({
            "success": False,
            "error": str(err),
            "credentials_missing": "AWS credentials were not detected" in str(err)
        }), 400

    except Exception as err:
        return jsonify({"success": False, "error": f"Unexpected scan error: {str(err)}"}), 500


@app.route("/api/export/json", methods=["GET"])
def export_json():
    data = latest_scan.get("results")
    if not data:
        return jsonify({"error": "No scan results available to export. Run a scan first."}), 400

    json_str = json.dumps(data, indent=2)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=aws_security_report.json"}
    )


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    data = latest_scan.get("results")
    if not data or "findings" not in data:
        return jsonify({"error": "No scan findings available to export. Run a scan first."}), 400

    output = io.StringIO()
    fieldnames = ["service", "resource", "severity", "risk", "issue", "recommendation"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for item in data.get("findings", []):
        writer.writerow({
            "service": item.get("service", ""),
            "resource": item.get("resource", ""),
            "severity": item.get("severity", ""),
            "risk": item.get("risk", 0),
            "issue": item.get("issue", ""),
            "recommendation": item.get("recommendation", "")
        })

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=aws_security_findings.csv"}
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n" + "=" * 55)
    print(" AWS CLOUD SECURITY SCANNER - WEB DASHBOARD")
    print("=" * 55)
    print(f" Dashboard running at: http://127.0.0.1:{port}")
    print(" Press Ctrl+C to stop the server.")
    print("=" * 55 + "\n")
    app.run(host="127.0.0.1", port=port, debug=True)
