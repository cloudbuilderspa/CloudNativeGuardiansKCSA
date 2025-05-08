# Main Concepts: Monitoring, Logging, and Runtime Security

Effective security doesn't stop at deployment. Continuous monitoring, comprehensive logging, and robust runtime security measures are essential for detecting, responding to, and mitigating threats in a live Kubernetes environment. This section covers these critical operational security aspects, relevant to the KCSA certification, drawing from domains like "Platform Security (Observability)" and "Cloud Native Security Overview."

## Introduction to Runtime Security

*   **What is Runtime Security?**
    Runtime security refers to the protection of applications and infrastructure *while they are running*. It focuses on detecting and responding to active threats, malicious behavior, and policy violations within live workloads and the cluster itself.

*   **Difference Between Pre-deployment Security and Runtime Security:**
    *   **Pre-deployment Security (Shift-Left):** Focuses on preventing vulnerabilities *before* deployment. This includes secure coding, image scanning, secure configuration of manifests, and IaC security.
    *   **Runtime Security:** Assumes that not all vulnerabilities can be caught pre-deployment and that new threats can emerge. It's about identifying and mitigating threats that manifest in the running environment.
    *   Both are crucial components of a defense-in-depth strategy.

## Continuous Monitoring for Threat Detection

*   **Importance:** Actively monitoring the cluster and its workloads is vital for early threat detection. Attackers may try to exploit vulnerabilities, escalate privileges, move laterally, or exfiltrate data. Continuous monitoring helps identify these actions.
*   **Key Areas to Monitor:**
    *   **Pod Behavior:** Unexpected process execution within containers, anomalous network connections from/to Pods, file system modifications, syscall anomalies.
    *   **Network Traffic:** Unusual traffic patterns between Pods, to/from external networks, port scanning, unexpected DNS queries.
    *   **API Server Access:** Unauthorized or suspicious API requests (monitored via Audit Logs), authentication failures, RBAC changes.
    *   **Node Activity:** Unusual processes on nodes, unauthorized access to node resources, Kubelet activity.
    *   **Container Runtime Activity:** Creation/deletion of containers, runtime errors that might indicate compromise.

## Logging for Security (Runtime Focus)

Comprehensive logging is the foundation for observability and incident response.

*   **Application Logs:**
    *   **What to Log:** Applications running in Pods should generate logs for security-relevant events: authentication attempts (success/failure), authorization decisions, significant business logic operations, errors, and input validation failures.
    *   **Best Practices:** Use structured logging (e.g., JSON) for easier parsing and analysis. Avoid logging sensitive data (passwords, PII, tokens) in plain text.
*   **Kubernetes Audit Logs:**
    *   **(Recap Importance):** As covered in Cluster Hardening, audit logs provide a detailed record of all API Server requests. They are crucial for tracking who did what, when, and to which resources.
    *   **Runtime Relevance:** Analyzing audit logs in real-time or near real-time can help detect ongoing attacks or policy violations (e.g., unauthorized Secret access, RBAC manipulation).
*   **Node Logs:**
    *   **OS-Level Logs:** Logs from the underlying operating system on worker and control plane nodes (e.g., `syslog`, `journald`, `auth.log`). These can reveal unauthorized login attempts to nodes, kernel-level exploits, or malware activity.
    *   **Container Runtime Logs:** Logs from the container runtime (Docker, containerd, CRI-O) can show errors or events related to container lifecycle management that might be security-relevant.
*   **Centralization and Analysis:**
    *   **Importance:** Manually checking logs on individual Pods or nodes is impractical. Logs from all sources (applications, API Server, nodes, runtimes) should be shipped to a centralized logging platform (e.g., Elasticsearch/Logstash/Kibana - ELK, Splunk, cloud provider logging services).
    *   **Benefits:** Enables correlation of events across different components, easier searching, long-term storage, and automated alerting based on log patterns.

## Security Metrics

Metrics provide quantitative insights into the security posture and can be used for alerting.

*   **Key Performance Indicators (KPIs) for Runtime Security:**
    *   Number of Pod Security Admission (PSA) violations (audit/warn/enforce).
    *   Rate of API Server authentication failures.
    *   Number of RBAC authorization denials.
    *   Anomalous network connection counts or volumes per Pod/Service.
    *   Number of alerts from runtime security tools (e.g., Falco).
    *   Resource exhaustion alerts (CPU, memory, disk) that might indicate a DoS or runaway process.
    *   Number of critical vulnerabilities detected in running images (if continuous scanning is in place).
*   **Monitoring Tools (Conceptual):**
    *   Tools like Prometheus can scrape metrics from Kubernetes components (API Server, Kubelet, etcd) and applications.
    *   Grafana can be used to visualize these metrics in dashboards, making it easier to spot trends and anomalies.
    *   Alertmanager (part of Prometheus ecosystem) can trigger alerts based on predefined thresholds for security metrics.
*   **KCSA Relevance:** Understand that collecting and analyzing security-related metrics is part of maintaining operational security awareness.

## Intrusion Detection and Prevention Systems (IDS/IPS) in Kubernetes Context

*   **IDS (Intrusion Detection System):** Monitors network and/or system activities for malicious activities or policy violations and reports them.
*   **IPS (Intrusion Prevention System):** Monitors like an IDS but can also actively block or prevent detected intrusions.
*   **Application in Kubernetes:**
    *   **Network IDS/IPS (NIDS/NIPS):** Can be deployed at the cluster ingress/egress points or within the cluster network (e.g., as part of a CNI plugin or service mesh) to monitor east-west traffic for known attack signatures or anomalous behavior.
    *   **Host-based IDS/IPS (HIDS/HIPS):** Deployed on individual nodes to monitor node-level activity, syscalls, and file system integrity. Runtime security tools often act as HIDS.
    *   **Runtime Security Tools as IDS:** Tools like Falco primarily function as an IDS, detecting policy violations or suspicious behavior at runtime and generating alerts. Some advanced systems might offer limited IPS capabilities.
*   **KCSA Relevance:** Understand the basic difference between IDS and IPS and how their principles apply to detecting and responding to threats in a Kubernetes environment.

## Common Runtime Security Tools (Conceptual Overview)

*   **Falco:**
    *   An open-source, cloud-native runtime security project, now a CNCF incubating project.
    *   Detects unexpected application behavior and alerts on threats at runtime.
    *   Uses syscalls as a primary data source via kernel modules or eBPF probes. Can also consume Kubernetes audit logs and other event sources.
    *   Uses a rule-based engine to define and detect suspicious activities (e.g., shell run in a container, unexpected network connection, sensitive file access).
*   **Sysdig Secure:**
    *   A commercial offering built on top of Falco and Sysdig open-source technologies.
    *   Provides broader runtime security capabilities including vulnerability management, compliance, threat detection, and forensics. Often includes more advanced features, a UI, and enterprise support.
*   **Other Categories:**
    *   **eBPF-based tools:** A growing number of tools leverage eBPF (extended Berkeley Packet Filter) for deep kernel-level observability and security enforcement with lower overhead (e.g., Cilium, Tracee).
    *   **Container Forensics Tools:** Tools designed to capture and analyze the state of a container after a security incident.
*   **KCSA Level Awareness:** Be aware of the existence and purpose of these tool categories, especially Falco as a prominent open-source example. Deep operational knowledge is not expected, but understanding their role in runtime security is.

## Basic Incident Response in Kubernetes

A high-level understanding of how to react when a runtime security alert occurs.
*   **When an Alert is Triggered:**
    1.  **Triage:** Validate the alert. Is it a true positive or a false positive?
    2.  **Containment:** If it's a true positive, the immediate goal is to contain the threat and prevent further damage or lateral movement.
        *   **Isolate Affected Pods/Nodes:**
            *   Apply restrictive Network Policies to the affected Pod(s).
            *   Cordon the node (`kubectl cordon <node-name>`) to prevent new Pods from being scheduled there.
            *   Potentially drain the node (`kubectl drain <node-name> --ignore-daemonsets`) after moving workloads if safe.
            *   Delete the compromised Pod(s) if necessary, but consider forensics first.
    3.  **Evidence Collection (Forensics):**
        *   Collect logs from the affected Pod, application, node, and API Server audit logs.
        *   Take a snapshot of the Pod's filesystem or the container's state if possible (advanced).
        *   Record network traffic if tools are in place.
    4.  **Eradication & Remediation:**
        *   Identify the root cause of the incident (e.g., exploited vulnerability, stolen credential).
        *   Patch vulnerabilities, update configurations, revoke compromised credentials.
    5.  **Recovery:**
        *   Restore affected services from a known good state (e.g., redeploy from a clean image, restore data from backup).
    6.  **Lessons Learned:** Conduct a post-incident review to improve security measures and response procedures.
*   **KCSA Relevance:** Understand the basic phases of incident response and how Kubernetes features (Network Policies, cordoning) can aid in containment.

## Ensuring Workload Integrity at Runtime

Verifying that running workloads have not been tampered with.
*   **File Integrity Monitoring (FIM):**
    *   **Concept:** Tools that monitor critical operating system and application files for unauthorized changes.
    *   **Application in Kubernetes:** Can be used on worker nodes to protect Kubelet files, container runtime files, or critical OS files. Can also be used within containers (though less common due to immutability principle) for specific use cases.
*   **Detecting Unexpected Process Execution or Network Connections:**
    *   Runtime security tools (like Falco) excel at this by monitoring syscalls.
    *   Alerts can be generated if a container starts an unexpected process (e.g., a shell, a network scanner) or makes an outbound connection to an unknown IP address.
*   **KCSA Relevance:** Appreciate that runtime security includes verifying the integrity of workloads and detecting deviations from expected behavior.

Effective monitoring, logging, and runtime security form a critical feedback loop, enabling organizations to detect threats that bypass preventative controls and respond swiftly to protect their Kubernetes clusters and applications.

