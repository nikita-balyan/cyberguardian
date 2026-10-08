from ..models.schemas import URLEvidence, RiskAssessment, QREvidence, MessageEvidence

def calculate_qr_risk(evidence: QREvidence) -> RiskAssessment:
    if not evidence.has_qr_code:
        return RiskAssessment(
            score=0,
            level="LOW",
            triggers=["No QR code detected"]
        )
    if not evidence.is_url or not evidence.url_evidence:
        return RiskAssessment(
            score=0,
            level="LOW",
            triggers=["QR code payload is not a URL"]
        )
    
    assessment = calculate_url_risk(evidence.url_evidence)
    assessment.triggers.insert(0, f"Decoded URL from QR code: {evidence.extracted_text}")
    return assessment

def calculate_message_risk(evidence: MessageEvidence) -> RiskAssessment:
    triggers = []
    score = 0
    
    if evidence.urgency_detected:
        score += 20
        triggers.append("Urgency or pressure tactics detected in text (+20)")
        
    if evidence.financial_lures_detected:
        score += 25
        triggers.append("Financial or credential lures detected in text (+25)")
        
    if evidence.suspicious_phone_or_sender:
        score += 15
        triggers.append("Suspicious phone number or spoofed sender pattern detected (+15)")
        
    # If there are any extracted URLs, find the highest risk score among them
    max_url_score = 0
    max_url_triggers = []
    for url_ev in evidence.url_evidences:
        url_risk = calculate_url_risk(url_ev)
        if url_risk.score > max_url_score:
            max_url_score = url_risk.score
            max_url_triggers = url_risk.triggers
            
    if max_url_score > 0:
        score += max_url_score
        triggers.append(f"High risk embedded URL detected with score {max_url_score}/100")
        for t in max_url_triggers:
            triggers.append(f"  [URL Trigger] {t}")
            
    score = max(0, min(100, score))
    
    if score >= 80:
        level = 'CRITICAL'
    elif score >= 60:
        level = 'HIGH'
    elif score >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'
        
    return RiskAssessment(
        score=score,
        level=level,
        triggers=triggers
    )

def calculate_url_risk(evidence: URLEvidence) -> RiskAssessment:
    triggers = []
    
    # Category 1: Threat Intelligence (Cap: 60)
    cat1_score = 0
    threat_intel = getattr(evidence, "threat_intel", None)
    threat_intel_flagged = False
    intel_feed_hits = 0
    if isinstance(threat_intel, dict):
        threat_intel_flagged = threat_intel.get("flagged", False)
        if threat_intel_flagged:
            intel_feed_hits = 1
    elif hasattr(threat_intel, "flagged"):
        threat_intel_flagged = threat_intel.flagged
        if threat_intel_flagged:
            intel_feed_hits = 1

    if evidence.safe_browsing_hit or threat_intel_flagged:
        cat1_score += 60
        intel_feed_hits = max(1, intel_feed_hits)
        if evidence.safe_browsing_hit:
            triggers.append("Safe Browsing threat intelligence hit (+60)")
        if threat_intel_flagged:
            summary_list = threat_intel.get("threat_summary", []) if isinstance(threat_intel, dict) else getattr(threat_intel, "threat_summary", [])
            if summary_list:
                for summary in summary_list:
                    triggers.append(f"External Threat Intelligence match: {summary} (+60)")
            else:
                triggers.append("External Threat Intelligence flagged this payload (+60)")
    cat1_score = min(60, cat1_score)

    # Category 2: Domain Age (Cap: 35)
    cat2_score = 0
    if evidence.domain_age_days is not None:
        if evidence.domain_age_days < 14:
            cat2_score += 25
            triggers.append(f"Domain age is very new ({evidence.domain_age_days} days < 14) (+25)")
        elif evidence.domain_age_days <= 30:
            cat2_score += 15
            triggers.append(f"Domain age is relatively new ({evidence.domain_age_days} days) (+15)")
    cat2_score = min(35, cat2_score)

    # Category 3: Brand Impersonation / Typosquatting (Cap: 25)
    cat3_score = 0
    if evidence.brand_impersonation:
        cat3_score += 25
        triggers.append("Potential brand impersonation or typosquatting detected (+25)")
    cat3_score = min(25, cat3_score)

    # Independent factors
    other_score = 0
    
    if not evidence.ssl_valid:
        other_score += 15
        triggers.append("Invalid or missing SSL certificate (+15)")
        
    if evidence.suspicious_tld:
        other_score += 10
        triggers.append("Suspicious TLD extension (+10)")
        
    if evidence.is_ip_address:
        other_score += 20
        triggers.append("Raw IP address used as hostname (+20)")
        
    if evidence.redirect_count > 2:
        other_score += 15
        triggers.append(f"Excessive HTTP redirects ({evidence.redirect_count} > 2) (+15)")

    # Heuristic score calculation
    heuristic_score = cat1_score + cat2_score + cat3_score + other_score
    heuristic_score = max(0, min(100, heuristic_score))

    # ML Probability and Score
    ml_prob = getattr(evidence, "ml_probability", None)
    if ml_prob is None:
        ml_prob = 0.1 if heuristic_score < 20 else 0.8
    ml_score = int(ml_prob * 100)
    
    # Only add ML probability trigger if there's a non-zero probability
    if ml_prob > 0:
        triggers.append(f"Machine Learning secondary classifier phishing probability: {ml_prob:.2f} (score: {ml_score}/100)")

    # Composite Risk Score Calculation
    composite_score = int(0.4 * heuristic_score + 0.4 * ml_score + 0.2 * (intel_feed_hits * 33))

    # Override: If Safe Browsing hit or threat intel flagged is true, minimum score is pinned to 95 (CRITICAL)
    if evidence.safe_browsing_hit or threat_intel_flagged:
        composite_score = max(composite_score, 95)

    # Clamp composite score between 0 and 100
    composite_score = max(0, min(100, composite_score))

    # Determine Level
    if composite_score >= 80:
        level = 'CRITICAL'
    elif composite_score >= 60:
        level = 'HIGH'
    elif composite_score >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return RiskAssessment(
        score=composite_score,
        level=level,
        triggers=triggers
    )

