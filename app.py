import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import anthropic

app = Flask(__name__, static_folder=".")
CORS(app)

API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are CyberGuard AI, an enterprise email security analyst.
When given an email, analyze it and respond in EXACTLY this format, nothing else:

VERDICT: [SAFE or PHISHING DETECTED or SUSPICIOUS]
RISK_SCORE: [number 0-100]
THREAT_LEVEL: [LOW or MEDIUM or HIGH or CRITICAL]
REASON_1: [specific reason]
REASON_2: [specific reason]
REASON_3: [specific reason]
ATTACKER_GOAL: [one sentence]
ACTION: [what employee should do]
SUMMARY: [2 sentences in plain English for non-technical staff]

Rules:
- Always use exact format above, no extra text
- Be specific, name exact suspicious elements
- If safe, list 3 things confirming it is legitimate
- Never ask questions, always give verdict immediately"""


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    email_text = data.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email provided"}), 400

    if not API_KEY:
        return jsonify({"error": "API key not set in .env file"}), 500

    try:
        client = anthropic.Anthropic(api_key=API_KEY)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Analyze this email:\n\n{email_text}"}
            ],
        )

        raw = message.content[0].text
        result = parse_response(raw)
        return jsonify(result)

    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid API key. Check your .env file."}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def parse_response(text):
    lines = text.strip().split("\n")
    result = {}
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return {
        "verdict":        result.get("VERDICT", "UNKNOWN"),
        "risk_score":     result.get("RISK_SCORE", "0"),
        "threat_level":   result.get("THREAT_LEVEL", "UNKNOWN"),
        "reasons":        [
            result.get("REASON_1", ""),
            result.get("REASON_2", ""),
            result.get("REASON_3", ""),
        ],
        "attacker_goal":  result.get("ATTACKER_GOAL", ""),
        "action":         result.get("ACTION", ""),
        "summary":        result.get("SUMMARY", ""),
    }


if __name__ == "__main__":
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        try:
            with open(".env") as f:
                for line in f:
                    if line.startswith("ANTHROPIC_API_KEY"):
                        os.environ["ANTHROPIC_API_KEY"] = line.split("=", 1)[1].strip()
                        break
        except FileNotFoundError:
            print("WARNING: .env file not found. Create one with your API key.")

    print("\n========================================")
    print("  GuardMail AI - Local Phishing Detector")
    print("  Running at: http://localhost:5000")
    print("  Press CTRL+C to stop")
    print("========================================\n")
    app.run(debug=False, port=5000)
