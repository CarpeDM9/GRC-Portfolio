# Cybersecurity Risk Assessment Project

## **1. Introduction**

This risk assessment evaluates the IT security posture a small e-commerce business handling customer data. The goal is to identify vulnerabilities, assess their impact, and recommend appropriate risk mitigation strategies to enhance security and compliance with industry standards such as [GDPR](https://en.wikipedia.org/wiki/General_Data_Protection_Regulation) and [ISO 27001](https://en.wikipedia.org/wiki/ISO/IEC_27001).

## **2. Risk Assessment Methodology**

This assessment follows ISO 27005 Risk Management ****framework for risk management, focusing on identifying threats, vulnerabilities, and their impact. Risks are ranked based on **impact (1-5)** and **likelihood (1-5)**, generating a final **risk level (Impact × Likelihood).**

## Scoring Criteria:

- **Low (Green)** → Acceptable risk, monitor periodically.
- **Medium (Yellow)** → Needs mitigation but not urgent.
- **High (Orange)** → Requires immediate action.
- **Critical (Red)** → Top priority; mitigate ASAP.

| Likelihood → \ Impact ↓ | 1 (Low) | 2 (Low-Med) | 3 (Medium) | 4 (High) | 5 (Critical) |
| --- | --- | --- | --- | --- | --- |
| 5 (Frequent) | Medium | High | High  | Critical | Critical |
| 4 (Likely) | Medium | Medium | High | High | Critical |
| 3 (Possible) | Low | Medium | Medium | High | High |
| 2 (Unlikely) | Low | Low | Medium | Medium | High |
| 1 (Rare) | Low | Low | Low | Medium | Medium |

[Probability Scores](Cybersecurity%20Risk%20Assessment%20Project%201a0ed1e0995180fcb21bf7e2f34b279e/Probability%20Scores%201a3ed1e0995180439998d4b938989bc7.csv)

[Impact Scores](Cybersecurity%20Risk%20Assessment%20Project%201a0ed1e0995180fcb21bf7e2f34b279e/Impact%20Scores%201a3ed1e0995180e8bc4dc2ca73963ea4.csv)

**Below is a structured risk register outlining key risks:**

[Risk Register](Cybersecurity%20Risk%20Assessment%20Project%201a0ed1e0995180fcb21bf7e2f34b279e/Risk%20Register%201a3ed1e099518047b063f10c427d3d1e.csv)

## **4. Risk Treatment Plan: P**roposed Mitigation Strategies

### **Mitigating Unauthorized Access (R-001 – High Risk)**

**Threat:** Unauthorized users gain access to sensitive systems or data, leading to breaches or misuse.

**Vulnerability:** Weak authentication methods, excessive permissions, and lack of access controls.

---

## **Mitigation Plan:**

## **Implement Strong Authentication Measures**

      **Multi-Factor Authentication (MFA)**

- Enforce **MFA for all users**, especially **privileged accounts**.
- Use **biometric authentication** (fingerprint/Face ID) where possible.
    
    **Password Security Best Practices**
    
- Require **strong passwords** (min. **12 characters, mix of uppercase, lowercase, numbers, symbols**).
- Implement **password expiration policies** (every **90 days** for critical accounts).
- Deploy a **password manager** to prevent reuse of compromised passwords.
- Use **passkeys** or **passwordless authentication** where feasible.
    
    **Account Lockout Policies**
    
- Configure systems to **lock accounts after 5 failed login attempts**.
- Implement **CAPTCHAs** to prevent brute-force attacks.

---

## **Enforce Role-Based Access Control (RBAC)**

       **Least Privilege Access**

- Grant users **only the access they need** for their role (Principle of Least Privilege – PoLP).
- Remove **default admin privileges** from standard accounts.
    
    **Separation of Duties (SoD)**
    
- Ensure **critical tasks require two or more users** to prevent fraud or insider threats.
- Implement **dual approval for sensitive actions** (e.g., financial transactions, security changes).
    
    **User Access Reviews**
    
- Conduct **quarterly access audits** to remove **inactive, unnecessary, or overprivileged accounts**.
- Require **manager approvals** for access changes.

---

## **Implement Strong Network & Endpoint Security Controls**

       **Zero Trust Architecture (ZTA)**

- Require **identity verification at every access request** (Zero Trust model).
- Enforce **device compliance checks** before granting access.
    
    **Privileged Access Management (PAM)**
    
- Use **PAM solutions** (e.g., **CyberArk, BeyondTrust**) to secure admin accounts.
- Implement **just-in-time (JIT) access**, granting elevated privileges only **when needed**.
    
    **Endpoint Security & Monitoring**
    
- Deploy **Endpoint Detection & Response (EDR)** solutions (e.g., **CrowdStrike, SentinelOne**).
- Enforce **automatic session timeouts** for inactive sessions.

---

## **Secure Remote Access & Cloud Environments**

      ** Virtual Private Network (VPN) & Secure Remote Access**

- Require **VPN with encryption (IPsec, SSL VPNs)** for remote employees.
- Use **zero-trust network access (ZTNA)** instead of traditional VPNs.
    
    **Cloud Access Security Broker (CASB)**
    
- Monitor and control access to **SaaS applications (Microsoft 365, Google Workspace)**.
- Detect **unauthorized logins from unusual locations**.
    
    **Geo-Blocking & IP Whitelisting**
    
- Restrict system access based on **geographic locations or specific IP addresses**.
- Block access from high-risk countries unless necessary.

---

## **Conduct Regular Security Training & Awareness**

       **User Awareness Training**

- Train employees on **identifying phishing attacks, social engineering, and insider threats**.
- Implement **simulated phishing campaigns** to reinforce awareness.
    
    **Incident Response Drills**
    
- Conduct **unauthorized access tabletop exercises** to test security responses.
- Ensure employees know how to report suspicious login attempts.

---

## ***Incident Response for Unauthorized Access***

***Detect:** Use **SIEM solutions (Splunk, Microsoft Sentinel, QRadar)** to monitor unusual login patterns.*

***Block:** Implement **automated account lockouts** and escalate suspicious login attempts.*

***Investigate:** Conduct **forensic analysis** to determine the attack method.*

***Remediate:** **Reset compromised accounts, update credentials, and improve access controls.***

***Prevent:** Enforce stricter authentication and monitoring controls based on attack findings.*

---

### **Mitigating Phishing Attacks (R-002 – High Risk)**

**Threat:** Cybercriminals use phishing emails to steal credentials or deploy malware.

**Vulnerability:** Employees lack phishing awareness and email security measures are weak.

## **Mitigation Plan:**

       **Security Awareness Training**

- Conduct **quarterly phishing simulation exercises** using platforms like **KnowBe4** or **Cofense**.
- Implement **mandatory cybersecurity training** during employee onboarding.

**Email Security Controls**

- Enable **Domain-based Message Authentication, Reporting & Conformance (DMARC), Sender Policy Framework (SPF), and DKIM** to prevent spoofing.
- Deploy an **AI-driven email security solution** (e.g., Microsoft Defender, Proofpoint).

**Multi-Factor Authentication (MFA)**

- Require **MFA for email accounts** to prevent compromised credential usage.
- Enforce **device-based authentication** for remote access.

### **Preventing Data Loss (R-003 – Medium Risk)**

**Threat:** Critical business data is lost due to system failure, accidental deletion, or ransomware.

**Vulnerability:** No data backup policy in place.

## **Mitigation Plan:**

       **Automated Cloud Backup Solution**

- Implement **daily automated backups** using AWS S3, Google Cloud, or Azure Backup.
- Store backups in an **air-gapped, immutable format** to prevent ransomware corruption.

**On-Premise & Off-Site Backup Strategy**

- Use the **3-2-1 backup rule**:
    - ***3 copies of data***
    - ***2 different storage types***
    - ***1 off-site backup (e.g., cloud storage, external data center).***
    
    **Disaster Recovery Testing**
    
- Conduct **quarterly recovery drills** to ensure backup integrity.
- Implement a **Business Continuity Plan (BCP)** to minimize downtime.

**Endpoint Protection & Ransomware Mitigation**

- Deploy **Next-Gen Antivirus (NGAV) & Endpoint Detection & Response (EDR)** solutions (e.g., CrowdStrike, SentinelOne).
- Restrict **USB device access** to prevent unauthorized data exfiltration.

### **Mitigating Distributed Denial of Service (DDoS) Attacks (R-004 – High Risk)**

**Threat:** Attackers flood the network or website with excessive traffic, causing service disruption.

**Vulnerability:** No traffic filtering or DDoS protection measures in place.

## **Mitigation Plan:**

      ** Deploy a Web Application Firewall (WAF)**

- Implement **Cloudflare, AWS WAF, or Imperva** to filter malicious traffic.
- Configure **rate limiting** to prevent traffic spikes from overwhelming servers.

**Use a DDoS Protection Service**

- Subscribe to a **DDoS mitigation service** like **AWS Shield, Cloudflare, or Akamai Kona Site Defender**.
- Enable **real-time traffic analysis** to detect and block attack patterns.

**Network Redundancy & Load Balancing**

- Use **Content Delivery Networks (CDNs)** to distribute traffic across multiple locations.
- Implement **load balancing** to distribute legitimate traffic and reduce bottlenecks.

**Implement Rate Limiting & Access Control**

- Set **API rate limits** to block excessive requests from a single IP.
- Configure **Geo-blocking** to restrict access from high-risk regions.

**Enable Auto-Scaling & Cloud-Based Resources**

- Use **auto-scaling cloud instances** (AWS Auto Scaling, Azure Scale Sets) to handle unexpected traffic spikes.
- Implement **failover solutions** to reroute traffic if the primary server is compromised.

**Continuous Monitoring & Threat Intelligence**

- Use **SIEM solutions** like **Splunk, Microsoft Sentinel, or Graylog** to monitor traffic patterns.
- Subscribe to **threat intelligence feeds** (e.g., FS-ISAC, IBM X-Force) to stay updated on emerging DDoS attack vectors.

---

## **Incident Response for DDoS Attacks**

***Detect Attack:** Monitor traffic spikes in **firewall logs, SIEM, and network monitoring tools**.*

***Activate Mitigation Measures:** Switch traffic through **DDoS protection providers** or **CDNs**.*

***Analyze & Block Attack Sources:** Identify attack patterns and block malicious IPs.*

***Restore Services:** Adjust load balancing and reroute traffic as needed.*

***Post-Incident Review:** Analyze logs and update defense strategies to prevent future attacks.*

### **Mitigating Insider Threats (R-004 – High Risk)**

**Threat:** Employees, contractors, or trusted third parties intentionally or unintentionally compromise security, leading to data breaches, fraud, or sabotage.

**Vulnerability:** Lack of user monitoring, weak access controls, and inadequate security awareness.

---

## **Mitigation Plan:**

## **Implement Insider Threat Detection & Monitoring**

 **User & Entity Behavior Analytics (UEBA)**

- Deploy **UEBA solutions (Splunk UBA, Exabeam, Microsoft Defender for Identity)** to detect unusual behavior.
- Monitor for **abnormal login attempts, excessive file downloads, unauthorized system access**.

**Security Information and Event Management (SIEM)**

- Implement **real-time logging & alerts** for privileged user activity.
- Correlate logs across **HR, IT, and security systems** to detect suspicious trends.

 **Data Loss Prevention (DLP) Solutions**

- Block unauthorized file transfers to **USB drives, personal emails, cloud storage (Google Drive, Dropbox)**.
- Encrypt **sensitive documents** to prevent unauthorized sharing.

---

## **Enforce Strict Access Controls**

**Role-Based Access Control (RBAC) & Least Privilege**

- Limit **administrator rights** to only those who require them.
- Regularly review and revoke unnecessary access permissions.

**Privileged Access Management (PAM)**

- Use **PAM solutions (CyberArk, BeyondTrust)** for **session monitoring & just-in-time access**.
- Implement **break-glass procedures** to control emergency admin access.

**Separation of Duties (SoD)**

- Ensure **no single employee has full control over critical systems**.
- Require **dual approval for financial transactions, system changes, and high-risk actions**.

---

## **Strengthen Physical & Remote Security**

**Badge Access & CCTV Monitoring**

- Restrict entry to **server rooms, data centers, and other critical areas**.
- Monitor high-risk areas using **video surveillance & access logs**.

**Secure Remote Work Policies**

- Use **Virtual Desktop Infrastructure (VDI)** to limit local data storage.
- Restrict VPN access based on **location & device compliance**.

**Geo-Fencing & IP Whitelisting**

- Block logins from unauthorized locations.
- Allow system access **only from company-approved devices**.

---

## **Implement Insider Threat Awareness & Reporting**

 **Employee Security Training**

- Train employees to recognize signs of **malicious or negligent insider behavior**.
- Implement **whistleblower protection policies** to encourage safe reporting.

**Anonymous Insider Threat Reporting Mechanism**

- Set up a **confidential reporting system** for employees to flag suspicious activities.
- Use **AI-driven HR analytics** to detect behavioral red flags (e.g., sudden dissatisfaction, policy violations).

**Insider Threat Program & Background Checks**

- Conduct **pre-employment background screenings** for **criminal history, financial distress, and job history discrepancies**.
- Require **periodic re-evaluation** of employees in **sensitive roles** (e.g., finance, IT admin, executive leadership).

---

## **Incident Response for Insider Threats**

***Detect:** Use **SIEM & UEBA analytics** to identify **anomalous insider behavior**.*

***Investigate:** Conduct forensic audits on **system access, file movements, and login anomalies**.*

***Contain:** Suspend **suspected accounts** and revoke high-risk access.*

***Remediate:** Strengthen **access controls & security awareness training**.*

***Legal Action:** Work with **HR & Legal teams** to take disciplinary or legal action if necessary.*

---

## **5. Recommendations and Conclusion**

## **Executive Summary – GRC & IT Security Project**

## **Overview**

This project explores Governance, Risk, and Compliance (GRC) strategies to mitigate **insider threats, unauthorized access, and Distributed Denial-of-Service (DDoS) attacks**. The focus is on implementing industry best practices, risk management frameworks, and technical controls to enhance IT security and regulatory compliance.

## **Key Findings**

1. **Insider Threats:**
    - Often caused by **malicious insiders, negligent employees, or compromised accounts**.
    - Require a combination of **User Behavior Analytics (UEBA)**, **Least Privilege Access (PoLP)**, and **security awareness training**.
2. **Unauthorized Access:**
    - Weak access controls increase the risk of **data breaches and privilege misuse**.
    - Implementing **Zero Trust Architecture (ZTA)**, **Multi-Factor Authentication (MFA)**, and **Role-Based Access Control (RBAC)** strengthens security.
3. **DDoS Attacks:**
    - Target organizations by **overloading networks and disrupting services**.
    - **Web Application Firewalls (WAFs)**, **CDN-based DDoS mitigation**, and **rate limiting** help prevent attacks.

## **Recommendations**

- **Enhance insider threat detection** with AI-driven analytics and proactive monitoring.
- **Strengthen access control** through role-based permissions and conditional access policies.
- **Improve DDoS resilience** with cloud-based security solutions and automated attack mitigation.
- **Align with industry standards** (NIST 800-53, ISO 27001, CIS Controls) for compliance.
- **Implement robust incident response procedures** with SIEM tools and threat intelligence.

## **Conclusion**

This project underscores the critical role of **proactive security governance** in mitigating cybersecurity risks. By implementing **Zero Trust principles, continuous monitoring, and automated threat detection**, organizations can significantly enhance their **security posture and compliance readiness**.

## **6. Appendix**

**Glossary of Terms**: Definitions of key risk assessment terms.

### **A**

- **Access Control** – Security measures restricting user access to systems, files, or networks based on defined permissions.
- **Anomaly Detection** – Identifying unusual patterns in user behavior that may indicate malicious activity.
- **Authentication** – The process of verifying the identity of a user, device, or system before granting access.

### **B**

- **Brute Force Attack** – A hacking method that attempts to guess passwords or encryption keys by systematically trying all possible combinations.

### **C**

- **Cloud Access Security Broker (CASB)** – Security solutions that monitor and control access to cloud applications to prevent unauthorized access.
- **Content Delivery Network (CDN)** – A distributed network of servers that deliver web content based on the geographic location of the user.
- **Cyber Threat Intelligence (CTI)** – The collection and analysis of information to anticipate and respond to cyber threats.

### **D**

- **Data Loss Prevention (DLP)** – A security strategy that detects and prevents the unauthorized transmission of sensitive data.
- **Denial-of-Service (DoS) Attack** – A cyberattack that overwhelms a network or system to disrupt its functionality.
- **Distributed Denial-of-Service (DDoS) Attack** – A DoS attack carried out using multiple devices to flood a target with excessive traffic.

### **E**

- **Endpoint Detection and Response (EDR)** – A cybersecurity solution that detects and responds to threats at the endpoint level, such as laptops and mobile devices.
- **Encryption** – The process of converting data into a coded format to protect it from unauthorized access.

### **F**

- **Firewall** – A security system that monitors and controls incoming and outgoing network traffic based on security rules.
- **Forensic Audit** – An investigative examination of security logs and system records to determine the cause of a security breach.

### **G**

- **Geo-Blocking** – Restricting access to a system or website based on the geographical location of the user.

### **I**

- **Insider Threat** – A security risk that originates from employees, contractors, or trusted third parties who misuse their access to harm an organization.
- **Incident Response (IR)** – A structured approach for handling security incidents, breaches, or cyberattacks.
- **IP Whitelisting** – Allowing access to a network or system only from pre-approved IP addresses.

### **J**

- **Just-in-Time (JIT) Access** – Granting users temporary privileged access only when needed, reducing exposure to security risks.

### **L**

- **Least Privilege Principle (PoLP)** – The security practice of granting users the minimal level of access necessary to perform their job functions.
- **Load Balancer** – A system that distributes network traffic across multiple servers to prevent overloading and ensure availability.

### **M**

- **Malware** – Malicious software designed to disrupt, damage, or gain unauthorized access to computer systems.
- **Memcached Amplification Attack** – A type of DDoS attack that exploits misconfigured Memcached servers to send massive amounts of traffic to a target.
- **Multi-Factor Authentication (MFA)** – A security process requiring two or more verification methods before granting access to a system.

### **N**

- **Network Segmentation** – Dividing a network into smaller sections to limit unauthorized access and contain cyber threats.
- **Non-Repudiation** – A security principle ensuring that an action (e.g., sending a message or making a transaction) cannot be denied by its originator.

### **P**

- **Passkey** – A passwordless authentication method that uses cryptographic keys for secure logins.
- **Privileged Access Management (PAM)** – Security tools and policies designed to protect and monitor administrative access to critical systems.
- **Phishing** – A social engineering attack that tricks individuals into revealing sensitive information through fraudulent emails or messages.

### **R**

- **Rate Limiting** – A security measure that restricts the number of requests a user or system can make within a given time frame.
- **Risk-Based Authentication (RBA)** – An adaptive authentication system that evaluates the risk level of a login attempt before granting access.

### **S**

- **Security Information and Event Management (SIEM)** – A security system that collects, analyzes, and correlates log data to detect threats in real time.
- **Separation of Duties (SoD)** – A control measure ensuring that no single individual has full control over critical operations to prevent fraud or misuse.
- **Session Timeout** – Automatically logging out inactive users to reduce the risk of unauthorized access.
- **Shadow IT** – The use of unauthorized software or devices within an organization, increasing security risks.
- **Social Engineering** – Manipulating individuals into revealing confidential information or taking actions that compromise security.

### **T**

- **Threat Intelligence** – The collection and analysis of data to understand potential cyber threats and vulnerabilities.
- **Two-Factor Authentication (2FA)** – A type of MFA that requires users to verify their identity using two separate authentication methods.

### **U**

- **User and Entity Behavior Analytics (UEBA)** – AI-driven security solutions that monitor user behavior to detect anomalies and potential threats.
- **Unauthorized Access** – When an individual or system gains entry to a resource without proper authorization.

### **V**

- **Virtual Private Network (VPN)** – A secure encrypted connection that protects data and enhances privacy over the internet.

### **Z**

- **Zero Trust Architecture (ZTA)** – A security model that requires continuous verification of users and devices before granting access to systems or data.
- **Zero-Day Exploit** – A cyberattack that targets a previously unknown vulnerability before a fix is available.

**Industry Standards & Frameworks**

1. **National Institute of Standards and Technology (NIST) Special Publications:**
    - NIST SP 800-53: *Security and Privacy Controls for Information Systems and Organizations*
    - NIST SP 800-171: *Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations*
    - NIST Cybersecurity Framework (CSF): *Framework for Improving Critical Infrastructure Cybersecurity*
    - [https://csrc.nist.gov/publications](https://csrc.nist.gov/publications)
2. **International Organization for Standardization (ISO) Standards:**
    - ISO/IEC 27001: *Information Security Management Systems (ISMS) Requirements*
    - ISO/IEC 27002: *Code of Practice for Information Security Controls*
    - https://www.iso.org/standard/27001
3. **Center for Internet Security (CIS) Controls:**
    - CIS Critical Security Controls v8
    - https://www.cisecurity.org/controls
4. **Information Technology Infrastructure Library (ITIL) Framework:**
    - ITIL v4: *Managing IT Service Security & Governance*
    - https://www.axelos.com/best-practice-solutions/itil

---

**Cybersecurity Threat Reports & Guidelines**

1. **MITRE ATT&CK Framework:**
    - *Knowledge Base of Tactics, Techniques, and Procedures (TTPs) Used by Cyber Adversaries*
    - https://attack.mitre.org
2. **Cybersecurity and Infrastructure Security Agency (CISA):**
    - CISA Insider Threat Mitigation Guide
    - CISA DDoS Attack Prevention Guidelines
    - [https://www.cisa.gov](https://www.cisa.gov/)
3. **Federal Trade Commission (FTC) – Data Security Guidelines:**
    - *FTC Safeguards Rule for Business Cybersecurity*
    - https://www.ftc.gov/business-guidance
4. **Verizon Data Breach Investigations Report (DBIR) – 2023 Edition:**
    - *Insights into Cyber Threats, Insider Threats, and Data Breaches*
    - https://www.verizon.com/business/resources/reports/dbir/
5. **IBM X-Force Threat Intelligence Index – 2023 Edition:**
    - *Cybersecurity Trends & Emerging Threats*
    - https://www.ibm.com/security/xforce
6. **Ponemon Institute – Cost of a Data Breach Report 2023:**
- *Financial Impact of Insider Threats & Security Breaches*
- https://www.ibm.com/security/data-breach

---

**Insider Threat & Access Control Best Practices**

1. **Carnegie Mellon University – CERT Insider Threat Center:**
- *Insider Threat Mitigation Strategies & Research*
- https://www.sei.cmu.edu/our-work/insider-threat/
1. **SANS Institute – Insider Threat Defense & DLP Whitepapers:**
- https://www.sans.org/white-papers/
1. **Microsoft Security – Zero Trust & Access Management:**
- *Identity & Access Management (IAM) and Conditional Access*
- [https://security.microsoft.com](https://security.microsoft.com/)
1. **Google Cloud Security – Data Loss Prevention (DLP):**
- *Cloud-Based Insider Threat & Access Controls*
- https://cloud.google.com/security
1. **Okta Identity Management – MFA & Privileged Access Best Practices:**
- https://www.okta.com/resources/

---

**DDoS Attack Prevention & Mitigation Strategies**

1. **Cloudflare DDoS Protection & Rate Limiting:**
- *DDoS Defense Strategies & Traffic Filtering*
- https://www.cloudflare.com/learning/ddos
1. **AWS Shield – DDoS Protection Best Practices:**
- [https://aws.amazon.com/shield](https://aws.amazon.com/shield)
1. **Google Project Shield – Web Security Against DDoS Attacks:**
- https://projectshield.withgoogle.com
1. **Imperva – Web Application Firewall (WAF) & DDoS Protection:**
- [https://www.imperva.com](https://www.imperva.com/)

---

**Security Tools & Technologies Referenced**

1. **Splunk SIEM & Insider Threat Analytics:**
- https://www.splunk.com/en_us/solutions/security.html
1. **CyberArk Privileged Access Management (PAM):**
- [https://www.cyberark.com](https://www.cyberark.com/)
1. **BeyondTrust PAM & Just-In-Time Access Control:**
- [https://www.beyondtrust.com](https://www.beyondtrust.com/)
1. **CrowdStrike Falcon – Endpoint Detection & Response (EDR):**
- [https://www.crowdstrike.com](https://www.crowdstrike.com/)
1. **Microsoft Sentinel – Cloud SIEM & Security Operations:**
- [https://www.microsoft.com/security/blog/microsoft-sentinel](https://www.microsoft.com/security/blog/microsoft-sentinel)

## Case Studies:

[Real World case study of Corporate Data Breach by an insider threat.](https://dl.acm.org/doi/10.1145/3546068#:~:text=The%20official%20announcement%20by%20Capital,intruder%20as%20well%20%5B11%5D)