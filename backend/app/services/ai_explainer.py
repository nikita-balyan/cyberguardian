import os
import google.generativeai as genai
from pydantic import BaseModel
from typing import List, Dict, Any

from app.config import GEMINI_API_KEY

class AIExplanation(BaseModel):
    summary: str
    why: List[str]
    what_to_do: List[str]
    educational_tip: str

class AIExplainer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or GEMINI_API_KEY
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None

    def _generate_fallback_explanation(self, evidence: Dict[str, Any], risk_assessment: Dict[str, Any]) -> AIExplanation:
        score = risk_assessment.get("score", 0)
        level = risk_assessment.get("level", "LOW")
        
        if self.model is not None:
            summary = "A default explanation was generated due to an issue with the AI service."
        else:
            summary = f"Analyzed risk level is {level} with a score of {score}/100."

        why = [
            f"Risk score: {score}",
            f"Severity: {level}"
        ]

        # Check evidence indicators
        if evidence.get("is_ssrf"):
            why.append("The request indicates potential SSRF activity.")
        if evidence.get("threat_intel_flagged"):
            why.append("Domain was flagged by threat intelligence databases.")
        if evidence.get("suspicious_tld"):
            why.append("Domain uses a highly suspicious top-level domain.")
        if not evidence.get("ssl_valid", True):
            why.append("The SSL certificate for the website is invalid or expired.")
        if evidence.get("brand_impersonation"):
            why.append("The URL looks like an impersonation of a trusted brand.")
        if evidence.get("redirect_count", 0) > 0:
            why.append(f"The link redirects {evidence.get('redirect_count')} time(s).")

        what_to_do = ["Exercise caution."]
        if level in ["HIGH", "CRITICAL"]:
            what_to_do.extend([
                "Do not enter passwords or sensitive information.",
                "Close the browser tab immediately.",
                "Report the sender of this link if received unsolicited."
            ])
        else:
            what_to_do.extend([
                "Verify the sender's identity through trusted channels.",
                "Avoid downloading any unsolicited attachments from this page."
            ])

        educational_tip = "Always inspect URLs carefully before clicking. Look for lookalike characters or missing security protocols like HTTPS."
        return AIExplanation(
            summary=summary,
            why=why,
            what_to_do=what_to_do,
            educational_tip=educational_tip
        )

    def generate_explanation(self, evidence: Dict[str, Any], risk_assessment: Dict[str, Any]) -> AIExplanation:
        if not self.model:
            return self._generate_fallback_explanation(evidence, risk_assessment)

        prompt = f"""
        You are an AI assistant specializing in cybersecurity and threat intelligence. Your task is to provide a clear, concise, and actionable explanation of a URL scan result.

        **Grounding Constraint:**
        - You MUST ONLY explain the provided evidence and risk assessment.
        - You MUST NEVER invent indicators or hallucinate threat information not present in the provided data.
        - You MUST NEVER change or re-calculate the risk score or severity. Use the provided risk score and severity as given.

        **Provided Evidence:**
        {evidence}

        **Provided Risk Assessment:**
        {risk_assessment}

        **Your Explanation MUST follow this structured output format:**
        summary: A short 1-2 sentence executive overview of the scan result.
        why: Bullet points explaining the exact evidence indicators (e.g., domain age, redirects, SSL status, brand spoofing, threat feed matches) and how they contribute to the risk.
        what_to_do: Step-by-step actionable guidance for the user (e.g., "Do not enter passwords", "Report sender", "Close this tab immediately").
        educational_tip: A learning note explaining a specific scam technique or cybersecurity concept relevant to the findings (e.g., explaining urgency lures, lookalike domains, or the importance of HTTPS).

        Ensure your response is in a JSON format that can be directly parsed.
        """

        try:
            response = self.model.generate_content(prompt)
            explanation_data = response.text.strip()
            # If the response contains markdown code block, clean it up
            if explanation_data.startswith("```json"):
                explanation_data = explanation_data[7:]
            if explanation_data.endswith("```"):
                explanation_data = explanation_data[:-3]
            explanation_data = explanation_data.strip()
            
            return AIExplanation.model_validate_json(explanation_data)
        except Exception as e:
            print(f"Gemini API call failed: {e}")
            return self._generate_fallback_explanation(evidence, risk_assessment)
