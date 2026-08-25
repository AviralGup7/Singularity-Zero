"""Business logic parameter tampering detector.

Analyzes responses for parameters that may be vulnerable to
price manipulation, quantity tampering, discount abuse, and
other business logic attacks. Detects endpoints that process
client-controlled values for financial or critical operations.
"""

import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
    meaningful_query_pairs,
    normalized_confidence,
)
from src.analysis.passive.extended_shared import record

logger = logging.getLogger(__name__)

# Price-related parameter names
PRICE_PARAM_NAMES = {
    "price",
    "amount",
    "cost",
    "total",
    "subtotal",
    "fee",
    "charge",
    "payment",
    "pay",
    "value",
    "sum",
    "rate",
    "unit_price",
    "unitprice",
    "item_price",
    "itemprice",
    "base_price",
    "baseprice",
    "final_price",
    "finalprice",
    "discount_amount",
    "discountamount",
    "tax_amount",
    "taxamount",
    "shipping_cost",
    "shippingcost",
    "handling_fee",
    "handlingfee",
    "service_fee",
    "servicefee",
}

# Quantity-related parameter names
QUANTITY_PARAM_NAMES = {
    "quantity",
    "qty",
    "count",
    "num",
    "number",
    "items",
    "units",
    "amount",
    "volume",
    "size",
    "limit",
    "max",
    "min",
}

# Discount/coupon parameter names
DISCOUNT_PARAM_NAMES = {
    "discount",
    "coupon",
    "promo",
    "voucher",
    "offer",
    "deal",
    "savings",
    "rebate",
    "cashback",
    "credit",
    "bonus",
}

# Financial operation path patterns
FINANCIAL_PATH_PATTERNS = re.compile(
    r"(?i)/(checkout|payment|billing|invoice|order|purchase|buy|cart|subscription|refund|transfer|withdraw|deposit|donate|tip|pay)(?:s|ment|ing|ed)?(?:/|$)"
)


def _check_price_in_body(body: str) -> list[str]:
    """Check response body for price/currency indicators.

    Args:
        body: Response body text.

    Returns:
        List of price indicator signals found in the body.
    """
    signals = []
    body_lower = body.lower()

    # Check for currency symbols
    if any(symbol in body for symbol in ("$", "€", "£", "¥", "₹", "₽")):
        signals.append("currency_symbol_present")

    # Check for price-like patterns (numbers with decimal places)
    if re.search(r"\$?\d+\.\d{2}", body):
        signals.append("price_pattern_detected")

    # Check for total/amount fields
    if any(kw in body_lower for kw in ('"total"', '"amount"', '"price"', '"cost"', '"subtotal"')):
        signals.append("price_field_in_response")

    # Check for discount/coupon fields
    if any(kw in body_lower for kw in ('"discount"', '"coupon"', '"promo"', '"savings"')):
        signals.append("discount_field_in_response")

    # Check for quantity fields
    if any(kw in body_lower for kw in ('"quantity"', '"qty"', '"count"', '"items"')):
        signals.append("quantity_field_in_response")

    return signals


def business_logic_tampering_detector(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Detect endpoints vulnerable to business logic parameter tampering.

    Analyzes URLs and responses for:
    - Price-related parameters in URLs
    - Quantity manipulation surfaces
    - Discount/coupon parameter exposure
    - Financial operation endpoints with client-controlled values
    - Price/quantity fields in JSON responses

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.

    Returns:
        List of business logic tampering findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    response_by_url = {str(r.get("url", "")).strip(): r for r in responses if r.get("url")}

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        tamper_params: list[str] = []

        # Check for financial operation paths
        path = urlparse(url).path or ""
        path_match = FINANCIAL_PATH_PATTERNS.search(path)
        if path_match:
            signals.append(f"financial_path:{path_match.group(1).lower()}")

        # Check for price-related query parameters
        query_pairs = meaningful_query_pairs(url)
        for name, value in query_pairs:
            name_lower = name.lower()

            # Price parameters
            if name_lower in PRICE_PARAM_NAMES:
                tamper_params.append(f"price:{name}")
                # Check for negative values (price manipulation)
                try:
                    if float(value) < 0:
                        signals.append(f"negative_price_in_param:{name}")
                except (ValueError, TypeError) as exc:
                    logger.debug("Ignored: %s", exc)

            # Quantity parameters
            if name_lower in QUANTITY_PARAM_NAMES:
                tamper_params.append(f"quantity:{name}")
                # Check for unusually large values
                try:
                    if int(value) > 9999:
                        signals.append(f"large_quantity_in_param:{name}")
                except (ValueError, TypeError) as exc:
                    logger.debug("Ignored: %s", exc)

            # Discount parameters
            if name_lower in DISCOUNT_PARAM_NAMES:
                tamper_params.append(f"discount:{name}")

        if tamper_params:
            signals.extend(tamper_params)

        # Check response for price/quantity indicators
        response = response_by_url.get(url)
        if response:
            body = str(response.get("body_text") or "")[:8000]
            if body:
                body_signals = _check_price_in_body(body)
                signals.extend(body_signals)

        # Only report if we have meaningful signals
        if len(signals) < 2:
            continue

        seen.add(endpoint_key)

        # Calculate risk score
        risk_score = 0
        if path_match:
            risk_score += 3
        if any("price:" in s for s in signals):
            risk_score += 4
        if any("quantity:" in s for s in signals):
            risk_score += 2
        if any("discount:" in s for s in signals):
            risk_score += 3
        if "negative_price_in_param" in signals:
            risk_score += 5
        if "large_quantity_in_param" in signals:
            risk_score += 3
        if "price_field_in_response" in signals:
            risk_score += 2
        if "currency_symbol_present" in signals:
            risk_score += 1

        severity = "high" if risk_score >= 8 else "medium" if risk_score >= 4 else "low"

        # Calculate confidence based on signal strength and evidence quality
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=signals,
            cap=0.92,
        )

        # Build human-readable explanation
        explanation_parts = []
        if path_match:
            explanation_parts.append(
                f"Financial operation path detected: {path_match.group(1).lower()}"
            )
        price_params = [s.split(":")[1] for s in signals if s.startswith("price:")]
        if price_params:
            explanation_parts.append(f"Price-related parameters found: {', '.join(price_params)}")
        quantity_params = [s.split(":")[1] for s in signals if s.startswith("quantity:")]
        if quantity_params:
            explanation_parts.append(
                f"Quantity-related parameters found: {', '.join(quantity_params)}"
            )
        if "negative_price_in_param" in signals:
            explanation_parts.append("Negative price value detected - potential price manipulation")
        if "large_quantity_in_param" in signals:
            explanation_parts.append("Unusually large quantity value detected")
        if "price_field_in_response" in signals:
            explanation_parts.append("Price fields present in response body")

        findings.append(
            record(
                url,
                status_code=response.get("status_code") if response else None,
                tampering_signals=signals,
                tamper_parameters=sorted(tamper_params),
                risk_score=risk_score,
                severity=severity,
                confidence=round(confidence, 2),
                explanation="; ".join(explanation_parts)
                if explanation_parts
                else "Business logic tampering surface detected",
                content_type=response.get("content_type", "") if response else "",
            )
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings


# Business logic active probe test cases
BUSINESS_LOGIC_TEST_CASES = [
    # Price manipulation tests
    {
        "param_type": "price",
        "test_values": ["-1", "0", "0.01", "999999999", "0.001", "-0.01"],
        "description": "Price manipulation",
    },
    # Quantity manipulation tests
    {
        "param_type": "quantity",
        "test_values": ["-1", "0", "999999", "1.5", "-100", "0.001"],
        "description": "Quantity tampering",
    },
    # Discount manipulation tests
    {
        "param_type": "discount",
        "test_values": ["100", "999", "-10", "100.5", "999999", "-100"],
        "description": "Discount abuse",
    },
    # Currency manipulation tests
    {
        "param_type": "currency",
        "test_values": ["USD", "EUR", "JPY", "XYZ", "123", ""],
        "description": "Currency manipulation",
    },
    # Payment method manipulation tests
    {
        "param_type": "payment_method",
        "test_values": ["credit_card", "paypal", "crypto", "bank_transfer", "gift_card", "free"],
        "description": "Payment method tampering",
    },
]


def business_logic_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Send safe business logic test payloads to financial parameters and check for acceptance.

    This probe sends harmless test values to price, quantity, and discount parameters
    to check if the server accepts manipulated values without proper validation.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of business logic probe findings.
    """
    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or is_noise_url(url):
            continue

        # Skip non-financial endpoints
        path = urlparse(url).path.lower()
        if not any(
            kw in path
            for kw in (
                "/checkout",
                "/payment",
                "/billing",
                "/order",
                "/purchase",
                "/cart",
                "/subscription",
                "/refund",
                "/transfer",
                "/donate",
            )
        ):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        # Get baseline response
        baseline = response_cache.get(url)
        if not baseline:
            continue

        baseline_status = int(baseline.get("status_code") or 0)

        # Find financial parameters
        query_pairs = list(meaningful_query_pairs(url))
        financial_params = []
        for name, value in query_pairs:
            name_lower = name.lower()
            if name_lower in PRICE_PARAM_NAMES:
                financial_params.append((name, value, "price"))
            elif name_lower in QUANTITY_PARAM_NAMES:
                financial_params.append((name, value, "quantity"))
            elif name_lower in DISCOUNT_PARAM_NAMES:
                financial_params.append((name, value, "discount"))

        if not financial_params:
            continue

        # Test each financial parameter with manipulation values
        probe_results = []
        for param_name, original_value, param_type in financial_params[:3]:  # Test up to 3 params
            test_cases = next(
                (tc for tc in BUSINESS_LOGIC_TEST_CASES if tc["param_type"] == param_type), None
            )
            if not test_cases:
                continue

            for test_value in test_cases["test_values"][:3]:  # Test first 3 values per param
                # Build mutated URL
                mutated_pairs = [(n, test_value if n == param_name else v) for n, v in query_pairs]
                mutated_query = "&".join(f"{n}={v}" for n, v in mutated_pairs)
                parsed = urlparse(url)
                mutated_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{mutated_query}"

                # Send probe request
                probe_response = response_cache.request(
                    mutated_url,
                    headers={"Cache-Control": "no-cache", "X-Business-Logic-Test": "1"},
                )

                if not probe_response:
                    continue

                probe_status = int(probe_response.get("status_code") or 0)
                probe_body = str(probe_response.get("body_text") or "")

                # Check if server accepted the manipulated value
                accepted = probe_status in (200, 201, 204, 302)
                rejected = probe_status in (400, 403, 422)

                # Check for error messages that indicate validation
                has_validation_error = any(
                    kw in probe_body.lower()
                    for kw in ["invalid", "error", "must be", "cannot be", "required"]
                )

                probe_results.append(
                    {
                        "parameter": param_name,
                        "original_value": original_value,
                        "test_value": test_value,
                        "param_type": param_type,
                        "probe_status": probe_status,
                        "accepted": accepted,
                        "rejected": rejected,
                        "has_validation_error": has_validation_error,
                        "mutated_url": mutated_url,
                    }
                )

        if not probe_results:
            continue

        # Analyze probe results
        accepted_probes = [
            r for r in probe_results if r["accepted"] and not r["has_validation_error"]
        ]
        rejected_probes = [r for r in probe_results if r["rejected"] or r["has_validation_error"]]

        issues = []
        if accepted_probes:
            issues.append(f"Server accepted {len(accepted_probes)} manipulated value(s)")
            for probe in accepted_probes[:3]:
                issues.append(
                    f"  - {probe['param_type']}:{probe['parameter']}={probe['test_value']} (status {probe['probe_status']})"
                )

        if rejected_probes:
            issues.append(f"Server properly rejected {len(rejected_probes)} manipulated value(s)")

        # Calculate risk score
        risk_score = 0
        if accepted_probes:
            risk_score += 5 * len(accepted_probes)
        if any(p["param_type"] == "price" and p["accepted"] for p in probe_results):
            risk_score += 10  # Price manipulation is highest risk
        if any(p["param_type"] == "discount" and p["accepted"] for p in probe_results):
            risk_score += 8
        if any(p["param_type"] == "quantity" and p["accepted"] for p in probe_results):
            risk_score += 6

        severity = "high" if risk_score >= 15 else "medium" if risk_score >= 5 else "low"
        confidence = normalized_confidence(base=0.50, score=risk_score, signals=issues, cap=0.95)

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "baseline_status": baseline_status,
                "probe_results": probe_results,
                "accepted_count": len(accepted_probes),
                "rejected_count": len(rejected_probes),
                "issues": issues,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": "; ".join(issues[:3])
                if issues
                else "Business logic probe completed",
            }
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings
