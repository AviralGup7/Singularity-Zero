"""Modern enterprise risk scoring domain.

Houses the new risk entities introduced to extend the legacy
``risk_score_engine`` / ``severity_model`` pair with:

* Asset registry and criticality tiers
* Business context configuration
* Compensating control tracking
* Risk acceptance governance
* Finding lifecycle state machine
* CVSS v4.0, EPSS, CISA KEV enrichment
* Normalised threat intel cache
* Composite remediation priority
"""

__all__: list[str] = []
