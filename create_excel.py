import pandas as pd

data = [
    ["Project Orchestration", "High-Level", "Red-Teaming Engine", "Core framework for managing adversarial simulations and security metrics", "Critical", "Implemented", "Complex"],
    ["Project Orchestration", "Low-Level", "RedTeamV2 Orchestrator", "Main class for executing test suites and merging multi-modal results", "Critical", "Implemented", "Medium"],
    
    ["Adversarial Attacks", "High-Level", "Attack Library", "Collection of diverse adversarial techniques for LLM stress testing", "High", "In-Progress", "High"],
    ["Adversarial Attacks", "Low-Level", "Linear Jailbreaking", "Iterative intensity scaling for complex jailbreak attempts", "High", "Implemented", "Medium"],
    ["Adversarial Attacks", "Low-Level", "Crescendo Jailbreaking", "Multi-turn trust-building attack; Sub-tasks: Using Deepteam Library", "High", "Implemented", "High"],
    ["Adversarial Attacks", "Low-Level", "Bad Likert Judge", "Semantic scoring analysis; Sub-tasks: Using Deepteam Library, Lib changes, Notebook conversion, Integration", "Medium", "Implemented", "Medium"],
    ["Adversarial Attacks", "Low-Level", "Prompt Injection", "Direct malicious instruction injection to override safety guardrails", "High", "Implemented", "Low"],
    ["Adversarial Attacks", "Low-Level", "Indirect Prompt Injection", "Testing for vulnerabilities where data contains hidden adversarial instructions", "Medium", "Planned", "Medium"],
    
    ["Vulnerability Engine", "High-Level", "Detection Framework", "Specialized checkers for security, privacy, and accuracy leaks", "Critical", "In-Progress", "Medium"],
    ["Vulnerability Checks", "Low-Level", "PII Leakage Detection", "Identification of sensitive personal data (Email, SSN, Phone) in responses", "Critical", "Implemented", "Medium"],
    ["Vulnerability Checks", "Low-Level", "BOLA Detection", "Detecting Broken Object Level Authorization and resource access patterns", "Critical", "Implemented", "High"],
    ["Vulnerability Checks", "Low-Level", "Prompt Leakage Detection", "Identifying extraction of internal system instructions or secret prompts", "High", "Implemented", "Medium"],
    ["Vulnerability Checks", "Low-Level", "Bias & Fairness Audit", "Systematic check for demographic bias or unfair demographic skewing", "Medium", "Planned", "High"],
    ["Vulnerability Checks", "Low-Level", "Misaccuracy Detection", "Detecting hallucinated facts or logically inconsistent responses", "High", "Planned", "High"],
    
    ["Platform & UI", "High-Level", "Streamlit UI", "Interactive dashboard for test orchestration and result visualization", "Medium", "Implemented", "Medium"],
    ["Platform & UI", "Low-Level", "Historical Analysis", "Detailed comparison of historical runs and JSON result viewers", "Medium", "Implemented", "Low"],
    
    ["Production Grade", "Roadmap", "Multi-tenant Auth", "Enterprise-grade user management and account-level security (e.g. Clerk/Auth0)", "Critical", "Planned", "High"],
    ["Production Grade", "Roadmap", "Scalable Task Queues", "Background processing for high-volume concurrent testing using Redis/Celery", "High", "Planned", "Medium"],
    ["Production Grade", "Roadmap", "Enterprise Observability", "Centralized logging, performance monitoring, and error tracking (Sentry/ELK)", "Medium", "Planned", "Medium"],
    ["Production Grade", "Roadmap", "API Gateway Security", "Secure handling of LLM credentials and encrypted data-at-rest", "Critical", "Planned", "Complex"],
    ["Production Grade", "Roadmap", "CI/CD Integration", "Automated security regression tests in the delivery pipeline", "Medium", "Planned", "Medium"]
]

columns = ["Category", "Task Level", "Task Name", "Description", "Priority", "Status", "Estimated Effort"]

df = pd.DataFrame(data, columns=columns)

# Save to Excel
output_path = "project_tasks.xlsx"
df.to_excel(output_path, index=False, engine='openpyxl')

print(f"Successfully updated {output_path} with sample.txt insights.")
