# Key Topics: Kubernetes Threat Model and System Hardening

This section expands on the Kubernetes Threat Model, delving into specific attack vectors, advanced persistence methods, and defense-in-depth strategies. A KCSA-level understanding of these topics is crucial for proactively hardening Kubernetes systems against real-world threats.

## Detailed Attack Vector Analysis

Understanding common attack vectors helps in designing better defenses.

### Scenario: Misconfigured `hostPath` Volume Leading to Node Compromise

*   **Concept:** `hostPath` volumes mount a file or directory from the host node's filesystem into a Pod. While sometimes necessary, they are dangerous if not properly restricted.
*   **Attack Vector:**
    1.  A Pod is configured with a `hostPath` volume mounting a sensitive host directory (e.g., `/`, `/etc`, `/var/lib/kubelet`, Docker socket path like `/var/run/docker.sock`).
    2.  If an attacker compromises this Pod (e.g., through an application vulnerability), they gain read/write access to the mounted host path *from within the container*.
    3.  With access to `/var/run/docker.sock`, an attacker can control the Docker daemon on the host, launch privileged containers, and effectively own the node.
    4.  Access to `/etc` could allow modification of critical system files or reading sensitive data. Access to Kubelet directories could lead to stealing credentials or compromising the Kubelet.
*   **KCSA Considerations &amp; Mitigation:**
    *   **Strictly Limit `hostPath` Usage:** Avoid `hostPath` volumes whenever possible.
    *   **Pod Security Standards (PSS):** `Baseline` and `Restricted` policies heavily restrict or disallow `hostPath` volumes to sensitive paths. Enforce these using Pod Security Admission (PSA).
    *   **`readOnly` Mounts:** If `hostPath` is unavoidable, mount it as `readOnly: true` if full write access is not needed.
    *   **Specific File Mounts:** Prefer mounting specific files rather than entire directories if only file access is needed.
    *   **RBAC:** Ensure that only highly trusted users/service accounts can create Pods that might use `hostPath`.

### Scenario: Exploiting a Vulnerable Application for Initial Access and Lateral Movement

*   **Concept:** An attacker exploits a known vulnerability (e.g., RCE, SQLi, SSRF) in an application running within a container to gain initial shell access.
*   **Attack Vector (Post-Exploitation):**
    1.  **Initial Shell:** Attacker gains a shell inside the compromised container.
    2.  **Information Gathering:**
        *   Check for mounted service account tokens (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
        *   Inspect environment variables for sensitive data.
        *   Scan the internal network for other accessible Pods/Services.
    3.  **Lateral Movement using Service Account Token:** If the Pod's service account has excessive RBAC permissions, the attacker can use the token with `kubectl` (if available or uploaded) or direct API calls to:
        *   List Secrets in the namespace or cluster-wide.
        *   Create new Pods (potentially privileged or with backdoors).
        *   Exec into other Pods.
    4.  **Network-Based Lateral Movement:** If Network Policies are not restrictive, the attacker can scan and attempt to exploit other services running within the cluster network.
*   **KCSA Considerations &amp; Mitigation:**
    *   **Application Security:** Secure coding, dependency scanning, web application firewalls (WAFs).
    *   **Least Privilege (RBAC):** Assign minimal permissions to service accounts.
    *   **Network Policies:** Implement default deny and allow only necessary traffic between Pods.
    *   **Pod Security Standards/`SecurityContext`:** Run containers as non-root, drop capabilities, use read-only root filesystems to limit attacker's capabilities even if they get a shell.
    *   **Runtime Security Monitoring:** Detect suspicious activity within containers.

### Scenario: Abusing Overly Permissive RBAC for Privilege Escalation

*   **Concept:** RBAC misconfigurations are a prime target for attackers to escalate privileges.
*   **Attack Vector:**
    1.  An attacker compromises a user account or service account with certain seemingly innocuous RBAC permissions.
    2.  These permissions, however, allow the attacker to grant themselves or another controlled identity more powerful permissions. Examples:
        *   Permission to create/update `(Cluster)RoleBindings`: Attacker can bind their controlled account to `cluster-admin`.
        *   Permission to create/update `(Cluster)Roles`: Attacker can add wildcard permissions (`*` on `*`) to a role they control or are bound to.
        *   Permission to use the `passimpersonate` verb on a privileged user/group.
        *   Permission to create Pods with `hostPID: true` or `hostIPC: true` which can be used to gain node access or interfere with other processes.
        *   Permission to create Pods that can use specific service accounts that are highly privileged.
*   **KCSA Considerations &amp; Mitigation:**
    *   **Regular RBAC Audits:** Periodically review all Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings.
    *   **Principle of Least Privilege:** Strictly adhere to granting only necessary permissions.
    *   **Restrict Modification of RBAC Objects:** Only highly trusted administrators should be ableto modify RBAC resources.
    *   **Monitor Audit Logs:** Watch for creation/modification of RBAC resources and suspicious impersonation events.

## Advanced Persistence Techniques in Kubernetes

Attackers use various methods to maintain long-term access.

### Using Mutating Admission Webhooks

*   **Concept:** Mutating Admission Webhooks can modify objects sent to the API Server before they are stored.
*   **Persistence Technique:** If an attacker can create or compromise a Mutating Admission Webhook, they can configure it to:
    *   Inject a malicious sidecar container into every new Pod created in certain namespaces.
    *   Modify Pod specs to mount sensitive host paths or use privileged security contexts.
    *   Add environment variables with backdoored commands.
*   **Mitigation:**
    *   Secure webhook server endpoints rigorously (TLS, authN, authZ).
    *   RBAC: Tightly control who can create or modify `MutatingWebhookConfiguration` objects.
    *   Monitor audit logs for changes to admission webhook configurations.
    *   Code review and secure deployment practices for webhook servers.

### Leveraging `initContainers` or Sidecars in Compromised Deployments/DaemonSets

*   **Concept:** If an attacker compromises a Deployment, StatefulSet, or DaemonSet definition (e.g., via CI/CD pipeline compromise or direct API access with sufficient privileges), they can add malicious `initContainers` or sidecar containers.
*   **Persistence Technique:**
    *   The malicious container runs alongside the legitimate application container.
    *   It can exfiltrate data, provide a reverse shell, or act as a pivot point.
    *   Since it's part of the workload definition, it will be automatically re-deployed if Pods are recreated.
*   **Mitigation:**
    *   GitOps: Use version control and review processes for all Kubernetes manifests.
    *   RBAC: Restrict write access to workload controllers.
    *   Image security: Ensure all containers (including init and sidecars) come from trusted sources and are scanned.
    *   Runtime security: Monitor behavior of all containers.

## Defense-in-Depth against Privilege Escalation

Preventing privilege escalation requires multiple layers of security controls.

*   **Concept:** Defense-in-depth means applying multiple, overlapping security controls so that if one control fails, others are still in place to thwart an attack.
*   **Key Layers in Kubernetes:**
    1.  **Strong Authentication &amp; Authorization (RBAC):** The first gate. Ensure least privilege for all users and service accounts.
    2.  **Pod Security Admission (PSA):** Enforce `Baseline` or `Restricted` Pod Security Standards to limit what Pods can do by default (e.g., prevent running as root, using hostPID/hostNetwork, privileged capabilities).
    3.  **`SecurityContext`:** Fine-tune security settings within Pods and containers (e.g., `runAsUser`, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`).
    4.  **Network Policies:** Restrict network access to limit lateral movement and access to sensitive services, even if a Pod is compromised.
    5.  **Runtime Security (Seccomp, AppArmor, SELinux):** Further restrict container actions at the kernel level by filtering syscalls and controlling access to resources.
    6.  **Node Hardening:** Secure the underlying host OS of worker nodes (minimize installed packages, apply security patches, use MAC like SELinux).
    7.  **Secure Container Runtimes:** Keep runtimes patched and securely configured.
    8.  **Audit Logging &amp; Monitoring:** Detect attempts at privilege escalation or suspicious activities.
*   **KCSA Relevance:** Understand that no single security control is foolproof. Layered security significantly increases the difficulty for an attacker to escalate privileges and compromise the cluster.

## Role of Network Segmentation in Mitigating Network Threats

Network Policies are a cornerstone of in-cluster network security.

*   **Preventing Sniffing/MitM within the Cluster:**
    *   While Network Policies operate at L3/L4, they can limit which Pods can even attempt to communicate with a target Pod. If an attacker compromises `Pod-A`, and `Pod-A` is not allowed to talk to `Pod-B` (which handles sensitive data), then the attacker cannot directly sniff or MitM `Pod-B`'s traffic from `Pod-A`.
    *   For true traffic encryption between Pods (protecting against a compromised node or sophisticated network attacker), a service mesh (e.g., Istio, Linkerd) providing mTLS is needed. Network Policies complement this by defining *who* can talk, while mTLS secures *how* they talk.
*   **Using Egress Policies for Data Exfiltration and C2 Prevention:**
    *   **Concept:** Egress policies control outbound connections *from* Pods.
    *   **Data Exfiltration Prevention:** By default, Pods can often connect to any IP address on the internet. A compromised Pod could exfiltrate sensitive data. Egress policies can restrict outbound connections to only known, legitimate external endpoints (e.g., specific database services, partner APIs).
    *   **Command &amp; Control (C2) Prevention:** Malware often tries to connect back to an attacker's C2 server. Restrictive egress policies can block these outbound C2 connections.
    *   **Example: Deny all egress, then allow specific:**
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-egress
          namespace: my-app-ns
        spec:
          podSelector: {}
          policyTypes:
          - Egress # This policy only affects Egress
          # No egress rules means all egress is denied
        ---
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: allow-dns-and-specific-external
          namespace: my-app-ns
        spec:
          podSelector:
            matchLabels:
              app: my-critical-app
          policyTypes:
          - Egress
          egress:
          - to: # Allow DNS to CoreDNS
            - namespaceSelector:
                matchLabels:
                  kubernetes.io/metadata.name: kube-system
              podSelector:
                matchLabels:
                  k8s-app: kube-dns
            ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          - to: # Allow access to a specific external service
            - ipBlock:
                cidr: 203.0.113.45/32
            ports:
            - port: 443
              protocol: TCP
        ```
*   **KCSA Relevance:** Effective use of Network Policies (both ingress and egress) is critical for limiting the blast radius of a network-based attack or a compromised Pod.

## Conceptual Application of Threat Modeling Frameworks (e.g., STRIDE)

*   **Concept:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is a common framework for categorizing and identifying threats.
*   **Applying STRIDE to a Kubernetes Component (e.g., Kubelet - Conceptual):**
    *   **Spoofing:** Could an attacker spoof Kubelet identity to the API Server? (Mitigation: Strong client certs for Kubelet). Could a malicious Pod spoof another Pod's identity to the Kubelet?
    *   **Tampering:** Could an attacker tamper with data Kubelet sends to API Server (Pod status)? (Mitigation: TLS). Could they tamper with Kubelet's configuration on the node? (Mitigation: Node hardening, file integrity monitoring).
    *   **Repudiation:** Does Kubelet log its actions sufficiently for auditing? Can actions be traced back?
    *   **Information Disclosure:** Does the Kubelet API (port 10250/10255) leak sensitive information if misconfigured? (Mitigation: Disable anonymous auth, restrict read-only port).
    *   **Denial of Service:** Can Kubelet be overwhelmed by too many Pods or API requests, impacting node stability? (Mitigation: Node resource limits, API server admission control).
    *   **Elevation of Privilege:** If Kubelet is compromised, can an attacker gain root on the node or control other Pods? (Mitigation: Run Kubelet with least privilege possible, NodeRestriction admission controller).
*   **KCSA Relevance:** While deep application of STRIDE is advanced, understanding that such frameworks exist and help systematically think about threats to components like Kubelet, API Server, or even deployed applications is valuable for a security mindset.

## Supply Chain Attacks as a Threat Vector

*   **Concept:** Attacks that target the software development lifecycle (build, test, package, deploy) to inject malicious code or compromise dependencies.
*   **Relevance to Kubernetes Threat Model:**
    *   **Compromised Container Images:** An attacker could push a malicious image to a public or private registry, or compromise a legitimate image by injecting malware. If these images are pulled and run in the cluster, they provide an initial foothold.
    *   **Vulnerable Dependencies:** Applications often use many third-party libraries. A vulnerability in one of these dependencies (e.g., Log4Shell) can be exploited once the application is containerized and deployed.
*   **Mitigation (Links to Supply Chain Security Domain):**
    *   Image scanning for vulnerabilities.
    *   Using trusted/verified base images.
    *   Image signing and verification (e.g., Notary, Sigstore).
    *   Software Bill of Materials (SBOM) to track dependencies.
    *   Secure CI/CD pipelines with checks and gates.
*   **KCSA Relevance:** Recognizing that threats can originate *before* workloads even reach the cluster is important. The integrity of container images and application dependencies is part of the overall threat landscape.

Understanding these key topics helps in developing a proactive and layered security strategy for Kubernetes, which is essential for mitigating risks identified through threat modeling.

