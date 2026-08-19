from ..models.schemas import URLEvidence, RiskAssessment

def calculate_url_risk(evidence: URLEvidence) -> RiskAssessment:
    triggers = []
    
    # Category 1: Threat Intelligence (Cap: 60)
    cat1_score = 0
    if evidence.safe_browsing_hit:
        cat1_score += 60
        triggers.append("Safe Browsing threat intelligence hit (+60)")
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

    # Total Score Calculation
    total_score = cat1_score + cat2_score + cat3_score + other_score

    # Override: If Safe Browsing hit is true, minimum score is pinned to 95
    if evidence.safe_browsing_hit:
        total_score = max(total_score, 95)

    # Clamp total score between 0 and 100
    total_score = max(0, min(100, total_score))

    # Determine Level
    if total_score >= 80:
        level = 'CRITICAL'
    elif total_score >= 60:
        level = 'HIGH'
    elif total_score >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return RiskAssessment(
        score=total_score,
        level=level,
        triggers=triggers
    )
