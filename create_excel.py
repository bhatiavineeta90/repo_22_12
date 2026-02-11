import pandas as pd

data = [
    # Category, Level, Task Name, Description, Assigned To, Priority, Status, Effort, Sub-Task 1, Sub-Task 2, Sub-Task 3, Sub-Task 4
    ["Core Framework", "High-Level", "Red-Teaming Orchestration Engine", "Establish the primary execution loop to manage simulation lifecycles and metric aggregation.", "Lead Architect", "Critical", "Implemented", "Complex", 
     "1. Design internal state machine for multi-turn sessions", "2. Implement multi-modal result merging logic", "3. Develop standardized logging interface for attack runners", "4. Optimize runner initialization for parallel execution"],
    
    # 5 Attacks
    ["Security Testing", "Low-Level", "Linear Jailbreaking Strategy", "Implement iterative intensity scaling to identify threshold-based security bypasses.", "Vineeta", "High", "Implemented", "Medium",
     "1. Configure jailbreak scoring threshold parameters", "2. Develop turn-based prompt mutation logic", "3. Integrate Deepteam evaluation metrics", "4. Validate against baseline safety filters"],
    ["Security Testing", "Low-Level", "Crescendo Multi-Turn Attack", "Simulate progressive trust-building conversation chains to bypass top-level safety layers.", "Vineeta", "High", "Implemented", "High",
     "1. Setup Deepteam library dependencies", "2. Script trust-building interaction sequences", "3. Implement response extraction for next-turn seeding", "4. Conduct full end-to-end integration testing"],
    ["Security Testing", "Low-Level", "Bad Likert Judge Evaluation", "Develop a specialized scoring mechanism to detect subtle semantic harms and bias.", "Vineeta", "Medium", "Implemented", "Medium",
     "1. Convert experimental notebook code to modular script", "2. Apply required changes to Deepteam library core", "3. Implement semantic scoring categorization", "4. Final review and dashboard integration"],
    ["Security Testing", "Low-Level", "Prompt Injection Modules", "Standardize payloads for direct instruction override and system instruction hijacking.", "Security Engineer", "High", "Implemented", "Low",
     "1. Curate baseline injection payload library", "2. Implement refusal detection logic", "3. Map successful injections to system instruction sets", "4. Standardize reporting format for injection success"],
    ["Security Testing", "Low-Level", "Indirect Prompt Injection Tests", "Evaluate system vulnerability to adversarial instructions hidden within third-party data.", "Security Intern", "Medium", "Planned", "Medium",
     "1. Research common data-based injection vectors", "2. Implement parser for data-embedded instructions", "3. Define success criteria for indirect hijacking", "4. Build playground environment for data testing"],

    # 5 Vulnerabilities
    ["Vulnerability Engine", "Low-Level", "PII Leakage Detection", "Automate detection of sensitive data leaks including emails, SSNs, and banking info.", "Privacy Lead", "Critical", "Implemented", "Medium",
     "1. Implement regex and NER-based PII scanners", "2. Define sensitivity levels for different data types", "3. Map PII hits to specific vulnerability profiles", "4. Generate auto-mitigation suggestions for developers"],
    ["Vulnerability Engine", "Low-Level", "BOLA Authorization Auditing", "Check for implementation flaws in object-level authorization and unofficial resource access.", "Backend Dev", "Critical", "Implemented", "High",
     "1. Define resource access pattern baselines", "2. Implement cross-user ID extraction logic", "3. Validate access tokens against resource ownership", "4. Report authorization bypass indicators"],
    ["Vulnerability Engine", "Low-Level", "Prompt Extraction Guardrails", "Monitor for unauthorized attempts to reveal internal system instructions or API keys.", "Lead Engineer", "High", "Implemented", "Medium",
     "1. Identify keyword-based leakage indicators", "2. Monitor for system message verbatim repetition", "3. Implement alert system for credential patterns", "4. Suggest system prompt hardening techniques"],
    ["Vulnerability Engine", "Low-Level", "Bias & Fairness Audit Module", "Audit LLM responses for demographic skews or unfair stereotypical representations.", "QA Engineer", "Medium", "Planned", "High",
     "1. Define demographic benchmark datasets", "2. Implement persona-based bias testing suites", "3. Measure statistical skews in response sentiment", "4. Benchmark against industry fairness standards"],
    ["Vulnerability Engine", "Low-Level", "Misaccuracy & Hallucination Check", "Identify factually incorrect or logically inconsistent responses during stress tests.", "Subject Matter Expert", "High", "Planned", "High",
     "1. Implement cross-referencing with ground truth data", "2. Build logical consistency checkers for long responses", "3. Implement confidence scoring for factual claims", "4. Flag high-risk hallucinatory patterns"],

    # Production Grade Roadmap
    ["Infrastructure", "Roadmap", "Multi-tenant Identity Management", "Implement secure user authentication and tenant-level data isolation.", "DevOps Team", "Critical", "Planned", "High",
     "1. Evaluate and integrate Clerk or Auth0", "2. Implement JWT-based RBAC for API endpoints", "3. Design tenant-isolated database schemas", "4. Audit session management for security gaps"],
    ["Infrastructure", "Roadmap", "Asynchronous Task Queuing", "Transition long-running simulations to background worker processes.", "Backend Team", "High", "Planned", "Medium",
     "1. Configure Redis and Celery worker infrastructure", "2. Implement task status polling endpoints", "3. Handle worker timeout and retry logic", "4. Optimize database connection pool for concurrent tasks"],
    ["Observability", "Roadmap", "Enterprise Logging & Monitoring", "Establish centralized monitoring for system health and performance analytics.", "DevOps Lead", "Medium", "Planned", "Medium",
     "1. Configure Sentry for real-time error tracking", "2. Set up ELK stack for centralized log analysis", "3. Develop system health heartbeat monitors", "4. Implement usage dashboards for resource tracking"],
    ["Production Security", "Roadmap", "API Gateway & Secret Management", "Protect LLM credentials and sensitive user data using enterprise-grade encryption.", "SecOps", "Critical", "Planned", "Complex",
     "1. Implement AWS/Azure Key Vault for API keys", "2. Set up rate limiting and API usage quotas", "3. Implement encryption-at-rest for results database", "4. Conduct external penetration test on API surface"],
    ["CI/CD", "Roadmap", "Automated Security Regression", "Integrate red-teaming tests directly into the developer deployment workflow.", "Release Engineer", "Medium", "Planned", "Medium",
     "1. Script headless execution of red-teaming suites", "2. Implement pass/fail criteria for PR approvals", "3. Integrate reporting with GitHub Actions", "4. Automate scheduled full-suite security audits"]
]

columns = ["Category", "Task Level", "Task Name", "Description", "Assigned To", "Priority", "Status", "Estimated Effort", "Sub-Task 1", "Sub-Task 2", "Sub-Task 3", "Sub-Task 4"]

df = pd.DataFrame(data, columns=columns)

# Save to Excel
output_path = "project_tasks.xlsx"
df.to_excel(output_path, index=False, engine='openpyxl')

print(f"Successfully generated updated {output_path} with human-like tasks and sub-tasks.")
