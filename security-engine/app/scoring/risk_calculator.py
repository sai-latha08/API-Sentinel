from typing import List, Dict, Any, Tuple
from app.schemas.models import SecurityFinding, EndpointDefinition, ScoreBreakdown, ScoreFactor

class RiskCalculator:
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25.0,
        "HIGH": 15.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
        "INFO": 1.0
    }

    @staticmethod
    def calculate_score(findings: List[SecurityFinding], endpoints: List[EndpointDefinition]) -> Tuple[int, str, ScoreBreakdown, Dict[str, int]]:
        if not findings and not endpoints:
            breakdown = ScoreBreakdown(
                base_score=0.0,
                critical_penalty=0.0,
                high_penalty=0.0,
                medium_penalty=0.0,
                low_penalty=0.0,
                info_penalty=0.0,
                sensitivity_multiplier=1.0,
                factors=[
                    ScoreFactor(name="Clean Baseline", impact="Positive", points=0.0, description="No endpoints or findings detected.")
                ]
            )
            return 0, "Excellent", breakdown, {}

        # Severity counts
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        critical_penalty = 0.0
        high_penalty = 0.0
        medium_penalty = 0.0
        low_penalty = 0.0
        info_penalty = 0.0

        for f in findings:
            sev = f.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
            weight = RiskCalculator.SEVERITY_WEIGHTS.get(sev, 5.0) * f.confidence
            if sev == "CRITICAL":
                critical_penalty += weight
            elif sev == "HIGH":
                high_penalty += weight
            elif sev == "MEDIUM":
                medium_penalty += weight
            elif sev == "LOW":
                low_penalty += weight
            elif sev == "INFO":
                info_penalty += weight

        # Raw penalty calculation
        raw_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty + info_penalty

        # Endpoint asset sensitivity multiplier
        avg_sensitivity = 0.0
        if endpoints:
            avg_sensitivity = sum(e.sensitivity_score for e in endpoints) / len(endpoints)
        
        # Multiplier ranges from 1.0 (low sensitivity) to 1.35 (high density of sensitive routes)
        sensitivity_multiplier = round(1.0 + (avg_sensitivity * 0.35), 2)
        adjusted_penalty = raw_penalty * sensitivity_multiplier

        # Normalization logic: Diminishing returns scaling to a 0-100 risk score
        # 1 Critical + 2 High = ~65 (High Risk)
        # 3+ Critical = 85-98 (Critical Risk)
        if adjusted_penalty <= 0:
            final_score = 5 # baseline clean score
        else:
            # S-curve / asymptotic normalization
            normalized = 100.0 * (1.0 - (1.0 / (1.0 + (adjusted_penalty / 35.0))))
            final_score = int(round(min(100.0, max(0.0, normalized))))

        # Determine Risk Level Category
        if final_score <= 20:
            risk_level = "Excellent"
        elif final_score <= 40:
            risk_level = "Good"
        elif final_score <= 60:
            risk_level = "Moderate"
        elif final_score <= 80:
            risk_level = "High Risk"
        else:
            risk_level = "Critical Risk"

        # Factors list for UI explainability
        factors: List[ScoreFactor] = []
        if counts["CRITICAL"] > 0:
            factors.append(ScoreFactor(
                name="Critical Severity Findings",
                impact="Negative",
                points=round(critical_penalty, 1),
                description=f"{counts['CRITICAL']} Critical vulnerability/exposure observation(s) identified (password hashes, unauthenticated admin)."
            ))
        if counts["HIGH"] > 0:
            factors.append(ScoreFactor(
                name="High Severity Findings",
                impact="Negative",
                points=round(high_penalty, 1),
                description=f"{counts['HIGH']} High risk item(s) detected (BOLA patterns, BFLA, SSRF, missing auth)."
            ))
        if counts["MEDIUM"] > 0:
            factors.append(ScoreFactor(
                name="Medium Severity Findings",
                impact="Moderate",
                points=round(medium_penalty, 1),
                description=f"{counts['MEDIUM']} Medium risk item(s) found (unbounded uploads, business logic risks, missing rate limit definitions)."
            ))
        if counts["LOW"] > 0 or counts["INFO"] > 0:
            factors.append(ScoreFactor(
                name="Low / Info Observations",
                impact="Minor",
                points=round(low_penalty + info_penalty, 1),
                description=f"{counts['LOW'] + counts['INFO']} low-severity hygiene or documentation observations."
            ))
        if sensitivity_multiplier > 1.05:
            factors.append(ScoreFactor(
                name="Attack Surface Exposure Factor",
                impact="Multiplier",
                points=sensitivity_multiplier,
                description=f"Specification contains high proportion of administrative, financial, and authentication routes ({round(avg_sensitivity * 100)}% sensitive)."
            ))

        breakdown = ScoreBreakdown(
            base_score=round(raw_penalty, 1),
            critical_penalty=round(critical_penalty, 1),
            high_penalty=round(high_penalty, 1),
            medium_penalty=round(medium_penalty, 1),
            low_penalty=round(low_penalty, 1),
            info_penalty=round(info_penalty, 1),
            sensitivity_multiplier=sensitivity_multiplier,
            factors=factors
        )

        # Calculate category scores (0-100 risk per category)
        cat_scores: Dict[str, int] = {}
        for f in findings:
            cat = f.category
            cat_scores[cat] = cat_scores.get(cat, 0) + int(RiskCalculator.SEVERITY_WEIGHTS.get(f.severity, 5) * f.confidence)

        return final_score, risk_level, breakdown, cat_scores
