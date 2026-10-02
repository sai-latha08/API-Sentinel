import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class BusinessLogicAnalyzer:
    FINANCIAL_FLOWS = ["payment", "charge", "refund", "transfer", "withdraw", "deposit", "payout", "wallet", "checkout"]
    INCENTIVE_FLOWS = ["coupon", "discount", "voucher", "reward", "promo", "cashback", "referral", "giftcard"]
    ACTION_FLOWS = ["vote", "poll", "claim", "subscribe", "like", "follow", "bid", "ticket"]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            path_lower = ep.path.lower()
            
            # Check Financial flows
            matched_financial = [w for w in BusinessLogicAnalyzer.FINANCIAL_FLOWS if w in path_lower]
            if matched_financial:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-BIZ-001",
                    title="Potential Sensitive Financial Business Flow Requiring Abuse Controls",
                    category="Business Logic & Anti-Abuse",
                    severity="HIGH",
                    confidence=0.88,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' performs critical financial/monetary operations ({', '.join(matched_financial)}). Sensitive financial transactions require multi-layered integrity controls, idempotency keys, and fraud prevention.",
                    evidence=f"Financial transaction keyword match: {matched_financial}. HTTP Method: {ep.method}.",
                    impact="Susceptibility to double-spend race conditions, negative quantity parameter tampering, currency rounding manipulation, and unauthorized balance drain.",
                    recommendation="Enforce idempotency keys (e.g. 'Idempotency-Key' header), distributed database row locking (or optimistic concurrency tokens), and server-side recalculation of prices/balances from database records rather than relying on client input.",
                    fix_code_example="""// Idempotency & Transaction Lock in Node.js
router.post('/payment/charge', authenticateToken, async (req, res) => {
  const idempotencyKey = req.headers['idempotency-key'];
  if (!idempotencyKey) {
    return res.status(400).json({ error: 'Idempotency-Key header is required' });
  }
  
  // Atomic distributed lock & transaction:
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    // Process transaction atomically...
    await session.commitTransaction();
  } catch (err) {
    await session.abortTransaction();
    throw err;
  }
});""",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                        "https://cwe.mitre.org/data/definitions/840.html"
                    ],
                    cwe_id="CWE-840",
                    owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows"
                ))

            # Check Coupon / Discount Incentive flows
            matched_incentives = [w for w in BusinessLogicAnalyzer.INCENTIVE_FLOWS if w in path_lower]
            if matched_incentives:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-BIZ-002",
                    title="Potential Coupon / Incentive Flow Vulnerable to Concurrency Abuse",
                    category="Business Logic & Anti-Abuse",
                    severity="MEDIUM",
                    confidence=0.84,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' processes promotional discounts or reward claims ({', '.join(matched_incentives)}). These workflows are frequent targets for automated coupon enumeration and concurrency race conditions.",
                    evidence=f"Promotional reward workflow matched: {matched_incentives}.",
                    impact="Users could send concurrent requests simultaneously to redeem a one-time promo code multiple times before database balances update.",
                    recommendation="Enforce atomic database updates (`$inc`, atomic compare-and-swap, or Redis distributed locks) and strict per-account redemption rate limits.",
                    fix_code_example="""// Atomic Coupon Redemption (MongoDB)
const result = await Coupon.findOneAndUpdate(
  { code: promoCode, isUsed: false, expiresAt: { $gt: new Date() } },
  { $set: { isUsed: true, usedBy: userId, redeemedAt: new Date() } },
  { new: true }
);

if (!result) {
  return res.status(400).json({ error: 'Promo code already redeemed or expired' });
}""",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
                    cwe_id="CWE-362",
                    owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows"
                ))

        return findings
