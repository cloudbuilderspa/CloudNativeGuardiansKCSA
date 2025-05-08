# Key Topics: Monitoring, Logging, and Runtime Security

This section delves deeper into advanced configurations, specific techniques, and tools for effective monitoring, logging, and runtime security in Kubernetes. These key topics build upon the main concepts and are essential for a KCSA-level understanding of maintaining a proactive and responsive security posture.

## Advanced Kubernetes Audit Policy Configuration

Kubernetes audit logs are a rich source of security information. A well-configured audit policy is crucial to capture relevant events without overwhelming storage or analysis capabilities.

*   **Audit Policy Structure Deep Dive:**
    *   **Rules:** An audit policy file consists of a list of rules. Each request to the API server is evaluated against these rules in order. The first matching rule determines the audit level for that request.
    *   **Levels:**
        *   `None`: Don't log events that match this rule.
        *   `Metadata`: Log request metadata (requesting user, timestamp, resource, verb, etc.) but not the request or response body.
        *   `Request`: Log event metadata and request body but not response body. Useful for all mutating requests.
        *   `RequestResponse`: Log event metadata, request body, and response body. Use sparingly as response bodies can be large, especially for `get` or `list` requests on large resources.
    *   **Stages:** Define at which stage of execution an event should be audited.
        *   `RequestReceived`: Generated as soon as the API server receives the request, before it's processed by the admission chain.
        *   `ResponseStarted`: Sent once the response headers are sent, but before the response body is sent.
        *   `ResponseComplete`: Sent when the response body has been completely sent and the connection is closed. This is the most common stage to log.
        *   `Panic`: Generated when a panic occurs.
*   **Examples of Rules for Specific Security Monitoring Goals:**
    *   **Track all `exec` commands:**
        ```yaml
        - level: RequestResponse
          resources:
          - group: "" # core API group
            resources: ["pods/exec"]
        ```
    *   **Track all Secret access (reads):**
        ```yaml
        - level: Request # Or RequestResponse if you need to see the secret content (use with caution)
          resources:
          - group: ""
            resources: ["secrets"]
          verbs: ["get", "list", "watch"]
        ```
    *   **Track all RBAC changes:**
        ```yaml
        - level: RequestResponse
          resources:
          - group: "rbac.authorization.k8s.io"
            resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
        ```
*   **Omitting Noisy but Low-Risk Events:**
    *   It's common to omit frequent, low-impact read requests, such as status updates from Kubelets or health checks.
        ```yaml
        - level: None
          users: ["system:kubelet"] # Example: omit Kubelet reads for its own node
          verbs: ["get", "watch"]
          resources:
          - group: ""
            resources: ["nodes"] # Be specific
        - level: None
          userGroups: ["system:nodes"]
          verbs: ["get"]
          resources:
          - group: ""
            resources: ["pods"] # Kubelet needs to get pods on its node
        ```
*   **KCSA Relevance:** Understand the structure of an audit policy file and how to define rules to capture critical security events while managing log volume.

## Integrating Logs and Metrics with SIEM/Observability Platforms

Centralizing logs and metrics is key for effective analysis and correlation.

*   **Conceptual Overview:**
    *   **Log Forwarding:** Agents (like Fluentd, Fluent Bit, Vector) are deployed on nodes (often as DaemonSets) to collect logs from various sources:
        *   Container logs (stdout/stderr, typically from `/var/log/pods/` or `/var/log/containers/`).
        *   Node system logs (`/var/log/messages`, `journald`).
        *   Kubernetes Audit Logs (from the file path specified in API server config).
        *   Application-specific log files.
    *   These agents then forward the logs to a centralized logging backend or SIEM (Security Information and Event Management) system like Elasticsearch (ELK Stack), Splunk, Sumo Logic, etc.
    *   **Metrics Scraping:** Prometheus is commonly used to scrape metrics from:
        *   Kubernetes components (API Server, Kubelet, Controller Manager, Scheduler, etcd).
        *   Node Exporter (for node-level OS metrics).
        *   Applications that expose metrics in a Prometheus-compatible format.
    *   Metrics are stored in Prometheus's time-series database and can be visualized with Grafana or fed into alerting systems.
*   **Benefits for Security:**
    *   **Correlation:** Ability to correlate events across different sources (e.g., an API audit event with a specific application log entry and a node-level process activity).
    *   **Advanced Querying & Analysis:** SIEMs provide powerful query languages and analytical tools to search through large volumes of log data.
    *   **Alerting:** Configure alerts in the SIEM or monitoring system for specific security events or anomalous patterns.
    *   **Long-Term Storage & Compliance:** Centralized systems can handle long-term storage and retention requirements for compliance.
*   **KCSA Relevance:** Understand the importance of centralization for logs and metrics and be aware of common architectural patterns (e.g., log forwarders, Prometheus for metrics).

## Anomaly Detection Strategies at Runtime

Identifying deviations from normal behavior can indicate a security incident.

*   **Beyond Rule-Based Detection:**
    *   While rule-based detection (e.g., Falco rules like "shell run in container") is effective for known bad behaviors, anomaly detection aims to identify *unknown* threats by learning a baseline of normal activity and flagging deviations.
*   **Techniques (Conceptual for KCSA):**
    *   **Process Activity Monitoring:** Baselining normal processes running in a container and alerting on new or unexpected process executions.
    *   **Network Connection Profiling:** Learning typical inbound/outbound network connections for a Pod/service and alerting on new or unusual connections (e.g., to a known malicious IP, unexpected ports).
    *   **Syscall Pattern Analysis:** Monitoring sequences or frequencies of system calls made by processes and identifying deviations from a learned baseline. This can be indicative of exploitation or malware.
    *   **User/Entity Behavior Analytics (UEBA):** For API server or user activity, baselining typical user actions and detecting anomalous behavior (e.g., a user suddenly accessing unusual resources, or performing actions at odd hours).
*   **Challenges:** Anomaly detection can be prone to false positives if the baseline is not well-established or if legitimate behavior changes frequently. It often requires a learning period.
*   **KCSA Relevance:** Understand the concept of anomaly detection as a complementary approach to rule-based detection for runtime security.

## The Role of eBPF in Runtime Security (Conceptual)

eBPF (extended Berkeley Packet Filter) is a powerful kernel technology revolutionizing observability and security.

*   **Brief Explanation of eBPF:**
    *   eBPF allows sandboxed programs to run directly in the Linux kernel without changing kernel source code or loading kernel modules.
    *   These eBPF programs can be attached to various kernel hook points (e.g., syscalls, network events, kprobes) to collect data or enforce policies with very low overhead.
*   **How eBPF Enables Runtime Security Tools:**
    *   **Deep Visibility:** eBPF provides granular visibility into kernel-level activities like syscalls, network packets, and process execution, which is invaluable for security monitoring.
    *   **Low Overhead:** Compared to older methods like kernel modules or ptrace, eBPF is generally more efficient and safer.
    *   **Security Enforcement:** eBPF can also be used to enforce security policies at the kernel level (e.g., blocking certain syscalls, dropping network packets).
    *   **Tools Leveraging eBPF:** Many modern cloud native security tools utilize eBPF, including:
        *   **Cilium:** For networking and network security (uses eBPF for routing, NetworkPolicies, load balancing).
        *   **Falco:** Can use an eBPF driver as an alternative to its kernel module for collecting syscall events.
        *   **Tracee, Pixie:** For runtime observability and security.
*   **KCSA Relevance:** Have a high-level awareness of what eBPF is and why it's an important enabling technology for modern runtime security and observability tools in cloud native environments.

## Container-Specific Incident Response Techniques

Responding to incidents in a containerized environment has unique aspects.

*   **Isolating a Compromised Pod/Node:**
    *   **Network Policies:** Immediately apply or update Network Policies to restrict all ingress and egress traffic for the compromised Pod or Pods matching its labels.
    *   **`kubectl cordon <node-name>`:** Marks the node as unschedulable, preventing new Pods from being placed on it. Existing Pods continue to run.
    *   **`kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data`:** Safely evicts Pods from the node (respecting PDBs) before maintenance or decommissioning. Use with caution during an incident if you need forensic data from the Pods.
    *   **Deleting/Scaling Down Pods:** If immediate threat removal is paramount and forensics are secondary or can be done from snapshots, deleting the Pod or scaling its controller (Deployment, StatefulSet) to zero can stop malicious activity.
*   **Forensic Data Collection from Containers:**
    *   **`kubectl logs <pod-name> [-c <container-name>]`:** Collect container logs.
    *   **`kubectl exec <pod-name> [-c <container-name>] -- <command>`:** If safe and the container is still running, exec in to run investigation commands (e.g., `ps`, `ls`, `netstat`). Be cautious as this can alter the state.
    *   **`kubectl cp <namespace>/<pod-name>:<path/to/file/in/container> <local/path>`:** Copy files out of a container.
    *   **Container Snapshotting/Checkpointing Tools:** Some container runtimes or specialized tools (e.g., CRIU with Docker/Podman, `kubectl-capture`) might allow for checkpointing a running container's state to disk for later analysis. This is more advanced.
*   **Importance of Ephemeral Nature:**
    *   Evidence can be lost quickly if a compromised Pod crashes, is evicted, or its node is terminated by an auto-scaler.
    *   Having robust centralized logging and monitoring is critical because the source of evidence might disappear.
*   **KCSA Relevance:** Understand basic Kubernetes commands for containment and be aware of methods for evidence collection from containers, recognizing the challenges posed by their ephemeral nature.

## Adherence to Benchmarks and Hardening Guides for Runtime Configurations

Ensuring runtime configurations align with security best practices.

*   **CIS Benchmarks for Kubernetes:**
    *   The Center for Internet Security (CIS) publishes widely respected benchmarks for Kubernetes, providing prescriptive guidance for hardening various components.
    *   These benchmarks cover runtime configurations for:
        *   Control Plane Components (API Server, Controller Manager, Scheduler, Etcd).
        *   Worker Node Components (Kubelet, Container Runtime).
        *   Network Policies, Pod Security Policies (deprecated but principles apply to PSA).
*   **Importance of Regular Review:**
    *   Configurations can drift over time due to manual changes or updates.
    *   Regularly audit your cluster configurations against relevant CIS Benchmarks (or other hardening guides like those from NSA/CISA).
    *   Tools like `kube-bench` can automate checking compliance with CIS Benchmarks.
*   **KCSA Relevance:** Be aware of the existence and importance of CIS Benchmarks as a source of best practices for secure Kubernetes configuration, including runtime aspects.

By mastering these key topics, individuals can significantly improve their ability to monitor, log effectively, and secure Kubernetes workloads at runtime, forming a critical part of a comprehensive KCSA skillset.

