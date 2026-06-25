import os
import email
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import google.generativeai as genai

app = Flask(__name__, static_folder=".")
CORS(app)

SYSTEM_PROMPT = """You are CyberGuard AI, an enterprise email security analyst specializing in header forensics and phishing detection.

When given an email (with or without headers), analyze it and respond in EXACTLY this format:

VERDICT: [SAFE or PHISHING DETECTED or SUSPICIOUS]
RISK_SCORE: [number 0-100]
THREAT_LEVEL: [LOW or MEDIUM or HIGH or CRITICAL]
HEADER_ANALYSIS: [If headers present: analyze SPF/DKIM/Return-Path/X-Originating-IP/Received chain. If no headers: write "No headers provided — body analysis only"]
REASON_1: [specific reason]
REASON_2: [specific reason]
REASON_3: [specific reason]
ATTACKER_GOAL: [one sentence]
ACTION: [what employee should do]
SUMMARY: [2 sentences in plain English for non-technical staff]

Rules:
- Always use exact format above, no extra text before or after
- For headers: check SPF pass/fail, DKIM signature, sender IP reputation, domain mismatch between From and Return-Path
- Be specific — name exact suspicious elements (e.g. domain typo, IP address, failed SPF)
- If safe, list 3 things confirming legitimacy
- Never ask questions, always give verdict immediately"""


def load_env():
    try:
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    os.environ[key.strip()] = value.strip()
    except FileNotFoundError:
        pass


load_env()


def parse_eml(raw_content):
    try:
        msg = email.message_from_string(raw_content)
        headers = []
        important = ["From","To","Subject","Date","Return-Path","Reply-To",
                     "Received","X-Originating-IP","X-Mailer","DKIM-Signature",
                     "Authentication-Results","Received-SPF","X-Spam-Status"]
        for h in important:
            val = msg.get(h)
            if val:
                headers.append(f"{h}: {val}")
        for h, v in msg.items():
            if h not in important:
                headers.append(f"{h}: {v}")
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    break
        else:
            body = msg.get_payload(decode=True)
            if isinstance(body, bytes):
                body = body.decode(errors="ignore")
            else:
                body = str(body) if body else ""
        return "\n".join(headers), body
    except Exception:
        return "", raw_content


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    email_text = data.get("email", "").strip()
    extra_headers = data.get("headers", "").strip()

    if not email_text:
        return jsonify({"error": "No email provided"}), 400

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return jsonify({"error": "GEMINI_API_KEY not found in .env file"}), 500

    parsed_headers = ""
    body = email_text

    if email_text.startswith("From ") or "MIME-Version" in email_text or "Content-Type:" in email_text:
        parsed_headers, body = parse_eml(email_text)

    combined = ""
    if parsed_headers or extra_headers:
        all_headers = (parsed_headers + "\n" + extra_headers).strip()
        combined = f"=== EMAIL HEADERS ===\n{all_headers}\n\n=== EMAIL BODY ===\n{body}"
    else:
        combined = f"=== EMAIL BODY (no headers provided) ===\n{body}"

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=SYSTEM_PROMPT
        )
        response = model.generate_content(f"Analyze this email:\n\n{combined}")
        raw = response.text
        result = parse_response(raw)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def parse_response(text):
    lines = text.strip().split("\n")
    result = {}
    current_key = None
    current_val = []
    for line in lines:
        if ":" in line and line.split(":")[0].replace("_","").isupper():
            if current_key:
                result[current_key] = " ".join(current_val).strip()
            current_key = line.split(":")[0].strip()
            current_val = [line.partition(":")[2].strip()]
        elif current_key:
            current_val.append(line.strip())
    if current_key:
        result[current_key] = " ".join(current_val).strip()

    return {
        "verdict":         result.get("VERDICT", "UNKNOWN"),
        "risk_score":      result.get("RISK_SCORE", "0"),
        "threat_level":    result.get("THREAT_LEVEL", "UNKNOWN"),
        "header_analysis": result.get("HEADER_ANALYSIS", ""),
        "reasons": [
            result.get("REASON_1", ""),
            result.get("REASON_2", ""),
            result.get("REASON_3", ""),
        ],
        "attacker_goal":   result.get("ATTACKER_GOAL", ""),
        "action":          result.get("ACTION", ""),
        "summary":         result.get("SUMMARY", ""),
    }


if __name__ == "__main__":
    api_key = os.environ.get("GEMINI_API_KEY")
    status = "API key loaded" if api_key else "ERROR: No API key found"
    print("\n========================================")
    print("  GuardMail AI - Local Phishing Detector")
    print("  Powered by Google Gemini (Free)")
    print(f"  Status: {status}")
    print("  Running at: http://localhost:5000")
    print("  Press CTRL+C to stop")
    print("========================================\n")
    app.run(debug=False, port=5000)
