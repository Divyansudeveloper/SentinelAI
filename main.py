from fastapi.middleware.cors import CORSMiddleware
import mailparser
import re as regex_module
import json
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from fastapi.responses import FileResponse
import uuid
import sqlite3
from datetime import datetime
import re
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
from groq import Groq
from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from PIL import Image
import pytesseract
import io
import os
import requests
from dotenv import load_dotenv
import cv2
import numpy as np
from pyzbar.pyzbar import decode

load_dotenv()

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
def init_db():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            text_snippet TEXT,
            final_verdict TEXT,
            malicious_confidence_pct INTEGER,
            conflict_detected INTEGER,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


def save_investigation(url, text, result):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO investigations (url, text_snippet, final_verdict, malicious_confidence_pct, conflict_detected, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        url,
        text[:200],  # sirf pehle 200 characters save karo, poora text nahi
        result.get("final_verdict"),
        result.get("malicious_confidence_pct"),
        int(result.get("conflict_detected", False)),
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()


def check_history(url):
    if not url.strip():
        return []
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT final_verdict, malicious_confidence_pct, timestamp
        FROM investigations
        WHERE url = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (url,))
    rows = cursor.fetchall()
    conn.close()
    return [{"verdict": r[0], "confidence": r[1], "checked_at": r[2]} for r in rows]


@app.get("/")
def home():
    return {"message": "SentinelAI is alive 🚀"}


@app.post("/agents/ocr")
async def ocr_agent(file: UploadFile = File(...)):
    image_bytes = await file.read()
    image = Image.open(io.BytesIO(image_bytes))
    extracted_text = pytesseract.image_to_string(image)
    return {
        "agent": "OCR",
        "filename": file.filename,
        "extracted_text": extracted_text.strip(),
        "text_length": len(extracted_text.strip())
    }


class URLRequest(BaseModel):
    url: str


@app.post("/agents/url")
def url_agent(request: URLRequest):
    headers = {"x-apikey": VT_API_KEY}

    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": request.url}
    )
    submit_data = submit_response.json()

    if "data" not in submit_data:
        return {
            "agent": "URL Intelligence",
            "error": True,
            "status_code": submit_response.status_code,
            "details": submit_data
        }

    analysis_id = submit_data["data"]["id"]

    result_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )
    result_data = result_response.json()

    if "data" not in result_data:
        return {
            "agent": "URL Intelligence",
            "error": True,
            "status_code": result_response.status_code,
            "details": result_data
        }

    stats = result_data["data"]["attributes"]["stats"]
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)

    if malicious_count > 0:
        verdict = "MALICIOUS"
        confidence = min(95, 50 + malicious_count * 5)
    elif suspicious_count > 0:
        verdict = "SUSPICIOUS"
        confidence = 60
    else:
        verdict = "CLEAN"
        confidence = 90

    return {
        "agent": "URL Intelligence",
        "url": request.url,
        "verdict": verdict,
        "confidence": confidence,
        "stats": stats
    }
@app.post("/agents/qr")
async def qr_agent(file: UploadFile = File(...)):
    # Image read karo
    image_bytes = await file.read()
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    # QR code decode karo
    decoded_objects = decode(img)

    if not decoded_objects:
        return {
            "agent": "QR Investigation",
            "found": False,
            "message": "Koi QR code nahi mila image me"
        }

    results = []
    for obj in decoded_objects:
        qr_data = obj.data.decode("utf-8")

        entry = {
            "type": obj.type,
            "data": qr_data,
            "is_url": qr_data.startswith("http")
        }

        # Agar QR ke andar URL hai, to URL Agent ko call karo real analysis ke liye
        if entry["is_url"]:
            url_check = url_agent(URLRequest(url=qr_data))
            entry["url_analysis"] = url_check

        results.append(entry)

    return {
        "agent": "QR Investigation",
        "found": True,
        "qr_codes": results
    }


class ScamTextRequest(BaseModel):
    text: str


@app.post("/agents/scam-pattern")
def scam_pattern_agent(request: ScamTextRequest):
    prompt = f"""Tum ek cyber fraud investigator ho. Neeche diya gaya text ek scam ho sakta hai. Isko analyze karo.

TEXT: "{request.text}"

Ye JSON format me jawab do (sirf JSON, aur kuch nahi, koi markdown formatting nahi):
{{
  "is_scam": true ya false,
  "scam_type": "OTP scam / Lottery scam / Investment scam / KYC scam / Bank scam / Job scam / Courier scam / Crypto scam / Phishing / None",
  "confidence": 0 se 100 ke beech ek number,
  "red_flags": ["red flag 1", "red flag 2"],
  "explanation": "1-2 line me kyu ye scam lag raha hai ya nahi"
}}"""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    ai_output = response.choices[0].message.content

    import json
    try:
        cleaned = ai_output.strip().strip("```json").strip("```").strip()
        parsed = json.loads(cleaned)
    except:
        parsed = {"raw_response": ai_output, "parse_error": True}

    return {
        "agent": "Scam Pattern Detection",
        "input_text": request.text,
        "analysis": parsed
    }


class InvestigationInput(BaseModel):
    text: str = ""
    url: str = ""


@app.post("/investigate")
def chief_investigator(input: InvestigationInput):
    evidence_log = []
    signals = []

    HIGH_SEVERITY_KEYWORDS = ["otp", "password", "bank account", "cvv", "pin", "aadhaar", "card number"]

    # ---- Agent 1: Scam Pattern ----
    scam_result = None
    if input.text.strip():
        scam_response = scam_pattern_agent(ScamTextRequest(text=input.text))
        scam_result = scam_response["analysis"]
        evidence_log.append({"agent": "Scam Pattern", "raw": scam_result})

        # Dynamic weight: agar red flags me high-severity keyword mile, weight badhao
        base_weight = 0.4
        red_flags_text = " ".join(scam_result.get("red_flags", [])).lower()
        combined_text_to_check = (red_flags_text + " " + input.text.lower())
        severity_boost = 0.15 if any(k in combined_text_to_check for k in HIGH_SEVERITY_KEYWORDS) else 0
        final_weight = base_weight + severity_boost

        signals.append({
            "source": "Scam Pattern Agent",
            "verdict": "MALICIOUS" if scam_result.get("is_scam") else "CLEAN",
            "confidence": scam_result.get("confidence", 50),
            "weight": final_weight,
            "weight_reason": "High-severity keyword mila (OTP/bank/password type) isliye weight boost hua" if severity_boost else "Standard weight"
        })

    # ---- Agent 2: URL Intelligence ----
    if input.url.strip():
        url_result = url_agent(URLRequest(url=input.url))
        evidence_log.append({"agent": "URL Intelligence", "raw": url_result})

        if not url_result.get("error"):
            signals.append({
                "source": "URL Intelligence Agent",
                "verdict": url_result["verdict"],
                "confidence": url_result["confidence"],
                "weight": 0.35,
                "weight_reason": "Standard weight — malware hosting ke liye reliable"
            })

    # ---- Agent 3: Domain Age ----
    if input.url.strip():
        domain_result = domain_age_agent(URLRequest(url=input.url))
        evidence_log.append({"agent": "Domain Age", "raw": domain_result})

        if domain_result.get("found"):
            risk_map = {"HIGH": ("MALICIOUS", 80), "MEDIUM": ("SUSPICIOUS", 55), "LOW": ("CLEAN", 85)}
            verdict, conf = risk_map[domain_result["risk"]]
            signals.append({
                "source": "Domain Age Agent",
                "verdict": verdict,
                "confidence": conf,
                "weight": 0.25,
                "weight_reason": f"Domain {domain_result['age_days']} din purana — {domain_result['note']}"
            })

    if not signals:
        return {"error": "Koi evidence nahi diya gaya (text ya url me se kam se kam ek chahiye)"}

    # ---- Weighted Fusion ----
    malicious_score = 0
    clean_score = 0
    total_weight = 0

    for sig in signals:
        weighted_conf = (sig["confidence"] / 100) * sig["weight"]
        total_weight += sig["weight"]
        if sig["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
            malicious_score += weighted_conf
        else:
            clean_score += weighted_conf

    final_malicious_pct = round((malicious_score / total_weight) * 100) if total_weight else 0
    final_clean_pct = round((clean_score / total_weight) * 100) if total_weight else 0

    verdicts_seen = set(s["verdict"] for s in signals)
    conflict_detected = ("CLEAN" in verdicts_seen) and (("MALICIOUS" in verdicts_seen) or ("SUSPICIOUS" in verdicts_seen))

    if final_malicious_pct >= 60:
        final_verdict = "HIGH RISK — Likely Fraud"
    elif final_malicious_pct >= 35:
        final_verdict = "MEDIUM RISK — Suspicious, Caution Advised"
    else:
        final_verdict = "LOW RISK — Likely Safe"

    explanation_parts = [
        f"{sig['source']} said '{sig['verdict']}' (confidence: {sig['confidence']}%, weight: {sig['weight']:.2f} — {sig['weight_reason']})"
        for sig in signals
    ]

    if conflict_detected:
        explanation_parts.append(
            "⚠️ CONFLICT DETECTED: Different agents returned different verdicts. "
            "This means the evidence is mixed — some signals suggest safety while others suggest risk."
        )

    past_history = check_history(input.url)

    save_investigation(input.url, input.text, {
        "final_verdict": final_verdict,
        "malicious_confidence_pct": final_malicious_pct,
        "conflict_detected": conflict_detected
    })

    return {
        "final_verdict": final_verdict,
        "malicious_confidence_pct": final_malicious_pct,
        "clean_confidence_pct": final_clean_pct,
        "conflict_detected": conflict_detected,
        "past_history": past_history,
        "individual_signals": signals,
        "explanation": explanation_parts,
        "raw_evidence": evidence_log
    }
@app.post("/agents/domain-age")
def domain_age_agent(request: URLRequest):
    try:
        domain = urlparse(request.url).netloc or request.url
        domain = domain.replace("www.", "")

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "agent": "Domain Age",
                "domain": domain,
                "found": False,
                "message": "WHOIS data nahi mila"
            }

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        # Severity logic: jitna naya domain, utna risky
        if age_days < 30:
            risk = "HIGH"
            note = "Domain 30 din se kam purana hai — scam sites me ye bahut common pattern hai"
        elif age_days < 180:
            risk = "MEDIUM"
            note = "Domain relatively naya hai (6 mahine se kam)"
        else:
            risk = "LOW"
            note = "Domain purana hai, established lagta hai"

        return {
            "agent": "Domain Age",
            "domain": domain,
            "found": True,
            "age_days": age_days,
            "risk": risk,
            "note": note
        }
    except Exception as e:
        return {
            "agent": "Domain Age",
            "found": False,
            "error": str(e)
        }
def extract_urls_from_text(text: str):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+)'
    return re.findall(url_pattern, text)


@app.post("/investigate/upload")
async def investigation_manager(file: UploadFile = File(...)):
    image_bytes = await file.read()

    # ---- Step 1: OCR chalao ----
    image = Image.open(io.BytesIO(image_bytes))
    extracted_text = pytesseract.image_to_string(image).strip()

    # ---- Step 2: QR code bhi try karo ----
    nparr = np.frombuffer(image_bytes, np.uint8)
    cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    qr_results = decode(cv_img)

    qr_urls = []
    for obj in qr_results:
        qr_data = obj.data.decode("utf-8")
        if qr_data.startswith("http"):
            qr_urls.append(qr_data)

    # ---- Step 3: Text me se URLs dhundo ----
    text_urls = extract_urls_from_text(extracted_text)

    # ---- Step 4: Sabse pehla mila hua URL choose karo (QR ko priority) ----
    all_urls = qr_urls + text_urls
    chosen_url = all_urls[0] if all_urls else ""

    # ---- Step 5: Chief Investigator ko bhejo ----
    investigation_result = chief_investigator(InvestigationInput(
        text=extracted_text,
        url=chosen_url
    ))

    return {
        "step_1_ocr_extracted_text": extracted_text,
        "step_2_qr_codes_found": qr_urls,
        "step_3_urls_found_in_text": text_urls,
        "step_4_url_chosen_for_analysis": chosen_url,
        "step_5_final_investigation": investigation_result
    }

def generate_pdf_report(investigation_data: dict, output_path: str):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, spaceAfter=20)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=14, spaceAfter=10, spaceBefore=15)
    normal_style = styles['Normal']

    # ---- Title ----
    elements.append(Paragraph("SentinelAI — Forensic Investigation Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%d %B %Y, %I:%M %p')}", normal_style))
    elements.append(Spacer(1, 20))

    # ---- Final Verdict Box ----
    verdict = investigation_data.get("final_verdict", "N/A")
    verdict_color = colors.red if "HIGH" in verdict else (colors.orange if "MEDIUM" in verdict else colors.green)

    verdict_table = Table([[f"FINAL VERDICT: {verdict}"]], colWidths=[450])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 15))

    # ---- Threat Score ----
    elements.append(Paragraph("Threat Score", heading_style))
    elements.append(Paragraph(
        f"Malicious Confidence: {investigation_data.get('malicious_confidence_pct')}% &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Clean Confidence: {investigation_data.get('clean_confidence_pct')}%",
        normal_style
    ))

    if investigation_data.get("conflict_detected"):
        elements.append(Spacer(1, 8))
        elements.append(Paragraph("⚠️ Conflicting signals detected across agents — see evidence details below.", normal_style))

    # ---- Evidence Summary ----
    elements.append(Paragraph("Evidence Summary", heading_style))
    for sig in investigation_data.get("individual_signals", []):
        elements.append(Paragraph(
            f"<b>{sig['source']}</b> — Verdict: {sig['verdict']}, Confidence: {sig['confidence']}%, Weight: {sig['weight']:.2f}",
            normal_style
        ))
        elements.append(Paragraph(f"<i>{sig['weight_reason']}</i>", normal_style))
        elements.append(Spacer(1, 8))

    # ---- Reasoning / Explanation ----
    elements.append(Paragraph("AI Reasoning", heading_style))
    for line in investigation_data.get("explanation", []):
        elements.append(Paragraph(f"• {line}", normal_style))
        elements.append(Spacer(1, 4))

    # ---- Past History ----
    past_history = investigation_data.get("past_history", [])
    if past_history:
        elements.append(Paragraph("Past Investigation History", heading_style))
        for h in past_history:
            elements.append(Paragraph(
                f"• {h['checked_at']}: {h['verdict']} (confidence: {h['confidence']}%)",
                normal_style
            ))

    # ---- Suggested Action ----
    elements.append(Paragraph("Suggested Action", heading_style))
    if "HIGH" in verdict:
        action_text = "Do NOT click any links or share personal/financial information. Report this to cybercrime.gov.in immediately. Preserve this evidence (screenshots, message headers) for complaint filing."
    elif "MEDIUM" in verdict:
        action_text = "Exercise caution. Do not share sensitive information. Verify the sender through official/independent channels before taking any action."
    else:
        action_text = "No immediate threat detected. Continue standard caution with unknown senders/links."
    elements.append(Paragraph(action_text, normal_style))

    doc.build(elements)


@app.post("/investigate/report")
def generate_report(input: InvestigationInput):
    investigation_result = chief_investigator(input)

    report_id = str(uuid.uuid4())[:8]
    output_path = f"report_{report_id}.pdf"

    generate_pdf_report(investigation_result, output_path)

    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename=f"SentinelAI_Report_{report_id}.pdf"
    )
class LegalAdviceRequest(BaseModel):
    scam_type: str = "Unknown"
    verdict: str = "MEDIUM RISK"


@app.post("/agents/legal-advisor")
def legal_advisor_agent(request: LegalAdviceRequest):
    prompt = f"""Tum ek Indian cyber law advisor ho. Ek user ko ye scam mila hai:

Scam Type: {request.scam_type}
Risk Level: {request.verdict}

Use practical, actionable legal guidance do India ke context me. JSON format me jawab do (sirf JSON, koi markdown nahi):
{{
  "applicable_laws": ["relevant IT Act sections ya IPC/BNS sections, jaise 'IT Act Section 66D - Cheating by personation using computer'"],
  "where_to_complain": ["jaise 'cybercrime.gov.in par online complaint file karo', 'National Cyber Crime Helpline: 1930'"],
  "evidence_to_preserve": ["jaise 'Screenshot poori chat ka', 'Sender ka phone number/email', 'Transaction ID agar payment hua ho'],
  "immediate_steps": ["jaise 'Bank ko turant inform karo agar paisa gaya ho', 'Password change karo agar credentials share hui hon'],
  "urgency": "HIGH / MEDIUM / LOW"
}}"""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    ai_output = response.choices[0].message.content

    try:
        cleaned = ai_output.strip().strip("```json").strip("```").strip()
        parsed = json.loads(cleaned)
    except:
        parsed = {"raw_response": ai_output, "parse_error": True}

    return {
        "agent": "Legal Advisor",
        "input": {"scam_type": request.scam_type, "verdict": request.verdict},
        "advice": parsed
    }

class EmailRequest(BaseModel):
    raw_headers: str


@app.post("/agents/email")
def email_intelligence_agent(request: EmailRequest):
    findings = {
        "spf": "NOT_FOUND",
        "dkim": "NOT_FOUND",
        "dmarc": "NOT_FOUND",
        "from_address": None,
        "reply_to_address": None,
        "reply_to_mismatch": False,
        "return_path": None,
        "red_flags": [],
        "risk_score": 0
    }

    headers_lower = request.raw_headers.lower()

    # ---- SPF Check ----
    spf_match = regex_module.search(r'spf=(\w+)', headers_lower)
    if spf_match:
        findings["spf"] = spf_match.group(1).upper()

    # ---- DKIM Check ----
    dkim_match = regex_module.search(r'dkim=(\w+)', headers_lower)
    if dkim_match:
        findings["dkim"] = dkim_match.group(1).upper()

    # ---- DMARC Check ----
    dmarc_match = regex_module.search(r'dmarc=(\w+)', headers_lower)
    if dmarc_match:
        findings["dmarc"] = dmarc_match.group(1).upper()

    # ---- From Address Extract ----
    from_match = regex_module.search(r'from:.*?<?([\w\.\-]+@[\w\.\-]+)>?', request.raw_headers, regex_module.IGNORECASE)
    if from_match:
        findings["from_address"] = from_match.group(1)

    # ---- Reply-To Extract ----
    reply_match = regex_module.search(r'reply-to:.*?<?([\w\.\-]+@[\w\.\-]+)>?', request.raw_headers, regex_module.IGNORECASE)
    if reply_match:
        findings["reply_to_address"] = reply_match.group(1)

    # ---- Return-Path Extract ----
    return_path_match = regex_module.search(r'return-path:.*?<?([\w\.\-]+@[\w\.\-]+)>?', request.raw_headers, regex_module.IGNORECASE)
    if return_path_match:
        findings["return_path"] = return_path_match.group(1)

    # ---- Reply-To Mismatch Detection (classic phishing sign) ----
    if findings["from_address"] and findings["reply_to_address"]:
        from_domain = findings["from_address"].split("@")[-1]
        reply_domain = findings["reply_to_address"].split("@")[-1]
        if from_domain != reply_domain:
            findings["reply_to_mismatch"] = True
            findings["red_flags"].append(
                f"From domain ({from_domain}) aur Reply-To domain ({reply_domain}) match nahi karte — classic phishing pattern"
            )

    # ---- Authentication Failures ----
    if findings["spf"] == "FAIL":
        findings["red_flags"].append("SPF check FAIL — sender server authorized nahi hai is domain ke liye")
    if findings["dkim"] == "FAIL":
        findings["red_flags"].append("DKIM check FAIL — email content ke saath chhedchhad ho sakti hai")
    if findings["dmarc"] == "FAIL":
        findings["red_flags"].append("DMARC check FAIL — domain policy violate ho rahi hai")

    # ---- Risk Score Calculation ----
    score = 0
    if findings["spf"] == "FAIL":
        score += 30
    if findings["dkim"] == "FAIL":
        score += 30
    if findings["dmarc"] == "FAIL":
        score += 20
    if findings["reply_to_mismatch"]:
        score += 25
    findings["risk_score"] = min(score, 100)

    if findings["risk_score"] >= 60:
        verdict = "HIGH RISK — Likely Spoofed/Phishing Email"
    elif findings["risk_score"] >= 30:
        verdict = "MEDIUM RISK — Some Red Flags Found"
    else:
        verdict = "LOW RISK — Authentication Looks Normal"

    return {
        "agent": "Email Intelligence",
        "verdict": verdict,
        "findings": findings
    }