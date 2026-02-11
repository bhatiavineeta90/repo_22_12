import pandas as pd

data = [
    ["Security Testing", "High-Level", "Red-Teaming Orchestration", "Core framework for managing adversarial simulations and metrics", "Critical", "Implemented", "Complex"],
    ["Security Testing", "High-Level", "Vulnerability Scanning", "Automated engine for detecting privacy and security leaks in LLM responses", "Critical", "Implemented", "Medium"],
    ["Adversarial Attacks", "Low-Level", "Linear Jailbreaking", "Iterative intensity scaling for complex jailbreak attempts", "High", "Implemented", "Medium"],
    ["Adversarial Attacks", "Low-Level", "Crescendo Jailbreaking", "Multi-turn trust-building attack to bypass safety filters", "High", "Implemented", "High"],
    ["Adversarial Attacks", "Low-Level", "Bad Likert Judge", "Semantic scoring attack to manipulate subjective LLM evaluations", "Medium", "Implemented", "Medium"],
    ["Adversarial Attacks", "Low-Level", "Prompt Injection", "Injection of malicious instructions to override system prompts", "High", "Implemented", "Low"],
    ["Adversarial Attacks", "Low-Level", "Indirect Prompt Injection", "Testing for vulnerabilities where data contains hidden instructions", "Medium", "Planned", "Medium"],
    ["Vulnerability Checks", "Low-Level", "PII Leakage Detection", "Identification of sensitive personal data (Email, SSN, Phone) in responses", "Critical", "Implemented", "Medium"],
    ["Vulnerability Checks", "Low-Level", "BOLA Detection", "Detecting Broken Object Level Authorization and resource access patterns", "Critical", "Implemented", "High"],
    ["Vulnerability Checks", "Low-Level", "Prompt Leakage Detection", "Identifying extraction of internal system instructions or secret prompts", "High", "Implemented", "Medium"],
    ["Vulnerability Checks", "Low-Level", "Bias & Fairness Audit", "Systematic check for demographic bias or unfair demographic skewing", "Medium", "Planned", "High"],
    ["Vulnerability Checks", "Low-Level", "Misaccuracy Detection", "Detecting hallucinated facts or logically inconsistent responses", "High", "Planned", "High"],
    ["Platform & UI", "High-Level", "Streamlit Dashboard", "Visual management interface for red-teaming runs and analytics", "Medium", "Implemented", "Medium"],
    ["Platform & UI", "Low-Level", "Real-time Visualization", "Dynamic progress bars and turn-by-turn result streams", "Low", "Implemented", "Low"],
    ["Platform & UI", "Low-Level", "JSON Export & History", "Detailed persistence and historical run comparison views", "Medium", "Implemented", "Low"],
    ["Production Grade", "Roadmap", "Multi-tenant Authentication", "Enterprise-grade user management and account-level security", "Critical", "Planned", "High"],
    ["Production Grade", "Roadmap", "Scalable Task Queues", "Background processing for high-volume concurrent testing (Redis/Celery)", "High", "Planned", "Medium"],
    ["Production Grade", "Roadmap", "Enterprise Observability", "Centralized logging and performance monitoring for production uptime", "Medium", "Planned", "Medium"],
    ["Production Grade", "Roadmap", "API Gateway Security", "Secure handling of LLM credentials and encrypted data-at-rest", "Critical", "Planned", "Complex"],
    ["Production Grade", "Roadmap", "CI/CD Integration", "Automated security regression tests in the delivery pipeline", "Medium", "Planned", "Medium"]
]

columns = ["Category", "Task Level", "Task Name", "Description", "Priority", "Status", "Estimated Effort"]

df = pd.DataFrame(data, columns=columns)

# Save to Excel
output_path = "project_tasks.xlsx"
df.to_excel(output_path, index=False, engine='openpyxl')

print(f"Successfully created {output_path}")
