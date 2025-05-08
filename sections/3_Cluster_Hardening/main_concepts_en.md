# Main Concepts: Kubernetes Security Fundamentals for Cluster Hardening

Cluster hardening involves applying a layered security approach to reduce the attack surface and minimize potential vulnerabilities within your Kubernetes environment. Understanding and implementing Kubernetes security fundamentals are key to achieving a hardened cluster. This section covers core concepts essential for KCSA, based on the "Kubernetes Security Fundamentals (22%)" domain.

## Pod Security Standards (PSS) and Pod Security Admission (PSA)

**Concept:**
*   **Pod Security Standards (PSS):** Define three distinct policy levels for Pods: `Privileged`, `Baseline`, and `Restricted`. These standards are designed to cover a broad spectrum of security requirements.
    *   `Privileged`: Unrestricted, allowing known privilege escalations. Should only be used for trusted, system-level workloads.
    *   `Baseline`: Minimally restrictive, preventing known privilege escalations while allowing for common application configurations. It's a good starting point for most workloads.
    *   `Restricted`: Highly restrictive, following current Pod hardening best practices. May require application refactoring for compatibility.
*   **Pod Security Admission (PSA):** A built-in Kubernetes admission controller that enforces PSS. PSA operates at the namespace level. When enabled, you can configure namespaces to `enforce`, `audit`, or `warn` upon Pod creation if they don't meet a specified PSS level.

**Importance for Cluster Hardening:**
*   PSS and PSA are crucial for preventing Pods from running with excessive privileges, which is a common vector for container escapes and privilege escalation within the cluster.
*   They provide a standardized way to apply security best practices to workloads consistently across namespaces.

**KCSA-Relevant Best Practices:**
*   Understand the different PSS levels and their implications.
*   Know how to configure PSA for namespaces to enforce, audit, or warn.
*   Aim to run workloads at the most restrictive PSS level possible (ideally `Restricted` or `Baseline`).
*   Avoid using the `Privileged` standard unless absolutely necessary for specific system components.

## Authentication Mechanisms

**Concept:**
Authentication is the process of verifying the identity of a user, service account, or process attempting to interact with the Kubernetes API Server. Kubernetes does not have a built-in user management system but relies on external methods or configured authenticators.
Common methods include:
*   **Client Certificates:** Users or services present a TLS certificate signed by the cluster's Certificate Authority (CA).
*   **Bearer Tokens:** A string presented with API requests. Examples include Service Account tokens (JWTs) or tokens from an OIDC provider.
*   **OpenID Connect (OIDC):** Integrates with external identity providers (like Google, Okta, Dex) allowing users to authenticate using their existing credentials.
*   **Webhook Token Authentication:** Delegates token verification to an external service.

**Importance for Cluster Hardening:**
*   Strong authentication ensures that only legitimate entities can attempt to access the cluster.
*   It's the first line of defense against unauthorized access.

**KCSA-Relevant Best Practices:**
*   Disable anonymous authentication (`--anonymous-auth=false` on API Server).
*   Use strong authentication methods; avoid static password files or basic authentication for user accounts if possible.
*   For Service Accounts, use projected, short-lived tokens where feasible (`TokenVolumeProjection`).
*   Securely manage client certificates and kubeconfig files.
*   Regularly review and audit authentication methods and user access.

## Authorization Mechanisms (Focus on RBAC)

**Concept:**
Authorization determines whether an *authenticated* entity is permitted to perform a specific action (e.g., create a Pod, read a Secret) on a specific resource. Kubernetes primarily uses Role-Based Access Control (RBAC).

*   **RBAC Components:**
    *   **Role:** A set of permissions within a specific namespace. Defines rules that represent a set of permissions (verbs: `get`, `list`, `create`, `update`, `delete`, etc.) on a set of resources (e.g., `pods`, `services`, `secrets`).
    *   **ClusterRole:** Similar to a Role, but its scope is cluster-wide. Can grant permissions on cluster-scoped resources (like `nodes`) or on namespaced resources across all namespaces.
    *   **RoleBinding:** Grants the permissions defined in a Role to a set of users, groups, or service accounts within a specific namespace.
    *   **ClusterRoleBinding:** Grants the permissions defined in a ClusterRole to subjects cluster-wide.

**Importance for Cluster Hardening:**
*   RBAC is fundamental for enforcing the Principle of Least Privilege, ensuring users and workloads only have the permissions they absolutely need.
*   It prevents privilege escalation and limits the blast radius if an account or service account token is compromised.

**KCSA-Relevant Best Practices:**
*   Always enable RBAC (`--authorization-mode=RBAC,...` on API Server).
*   Follow the Principle of Least Privilege: Grant minimal necessary permissions.
*   Prefer Roles and RoleBindings (namespaced) over ClusterRoles and ClusterRoleBindings where possible to limit scope.
*   Avoid granting `cluster-admin` privileges unless strictly necessary and for a very limited set of users/accounts.
*   Regularly audit RBAC configurations for overly permissive roles or bindings.
*   Use specific service accounts for applications rather than the `default` service account, and bind them to minimally privileged roles.
*   Common pitfalls: Binding users directly to ClusterRoles like `cluster-admin`, using wildcard permissions (`*`) excessively in roles.

## Secrets Management

**Concept:**
Kubernetes Secrets are objects designed to store and manage sensitive information, such as passwords, OAuth tokens, and SSH keys. They allow you to control how sensitive data is used and reduce the risk of accidental exposure.

**How Secrets are Stored:**
*   By default, Secrets are stored in `etcd` as base64-encoded strings. **Base64 is an encoding, not encryption.**
*   To protect Secrets effectively, encryption at rest for `etcd` data must be enabled. The API Server handles the encryption/decryption using an encryption provider.

**Importance for Cluster Hardening:**
*   Prevents hardcoding sensitive data directly into Pod specifications, container images, or application code.
*   Provides a controlled way to distribute sensitive data to Pods.

**KCSA-Relevant Best Practices:**
*   Enable encryption at rest for `etcd`.
*   Use RBAC to restrict access to Secrets. Only users and service accounts that need a specific Secret should have `get`, `list`, or `watch` permissions on it.
*   Prefer mounting Secrets as files into Pods rather than as environment variables. Environment variables can be more easily exposed through logs or child processes.
*   Avoid checking Secret manifests containing sensitive data directly into version control systems. Use tools like Sealed Secrets or external secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager) for managing secrets in GitOps workflows.
*   Regularly audit Secret access and rotate sensitive data where appropriate.

## Isolation and Segmentation

**Concept:**
Isolation and segmentation are techniques used to limit the "blast radius" if a component or workload is compromised. They prevent lateral movement by attackers and ensure that workloads only have access to the resources and network paths they need.

*   **Namespaces:**
    *   Provide a scope for names of resources. Resources in one namespace are isolated from resources in another (though not a strong security boundary by themselves for network traffic).
    *   Used to partition cluster resources between multiple users or teams.
    *   RBAC Roles are namespaced, allowing fine-grained access control within a namespace.
    *   ResourceQuotas and LimitRanges can be applied per namespace.
*   **Network Policies:**
    *   Provide L3/L4 network segmentation for Pods. They control how Pods are allowed to communicate with each other and with other network endpoints.
    *   Network Policies are implemented by the CNI (Container Network Interface) plugin. Not all CNI plugins support Network Policies.
    *   By default, if no Network Policies are applied to a Pod, all ingress and egress traffic is allowed to/from that Pod.
    *   **Key Mechanics:**
        *   `podSelector`: Selects the Pods to which the policy applies.
        *   `policyTypes`: Indicates if the policy applies to `Ingress`, `Egress`, or both.
        *   `ingress` rules: Define allowed incoming traffic.
        *   `egress` rules: Define allowed outgoing traffic.
        *   Rules can specify sources/destinations using `podSelector`, `namespaceSelector`, or `ipBlock`.
        *   Rules can specify ports and protocols.

**Importance for Cluster Hardening:**
*   Namespaces help organize resources and apply distinct security policies (RBAC, PSS, quotas).
*   Network Policies are critical for implementing a zero-trust network model within the cluster, reducing the risk of lateral movement by attackers.

**KCSA-Relevant Best Practices:**
*   Use namespaces to isolate different applications, environments (dev, staging, prod), or teams.
*   Implement a default-deny Network Policy for namespaces where appropriate, then explicitly allow required traffic.
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny-all
      namespace: my-secure-namespace
    spec:
      podSelector: {} # Selects all pods in the namespace
      policyTypes:
      - Ingress
      - Egress
      # No ingress or egress rules means all traffic is denied
    ```
*   Define granular Network Policies to allow only necessary communication between Pods and services.
*   Ensure your CNI plugin supports and enforces Network Policies.

## Audit Logging

**Concept:**
Audit logging provides a chronological record of calls made to the Kubernetes API Server. Each audit log entry contains information about who made the request, what action was performed, which resource was affected, and the outcome.

**Importance for Cluster Hardening:**
*   **Security Monitoring:** Detect suspicious activity, unauthorized access attempts, or policy violations.
*   **Incident Response:** Provide a trail of events to understand how a security incident occurred and what was affected.
*   **Compliance:** Meet regulatory or organizational compliance requirements for logging and auditing.

**KCSA-Relevant Best Practices:**
*   Enable audit logging on the API Server.
*   Configure an appropriate audit policy to capture relevant events without generating excessive noise. Key aspects of an audit policy:
    *   **Levels:** `None`, `Metadata` (request metadata only), `Request` (metadata and request body), `RequestResponse` (metadata, request, and response bodies).
    *   **Stages:** `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`. Log at least `ResponseComplete`.
*   Store audit logs securely, preferably in a centralized logging system outside the cluster, with appropriate retention policies and access controls.
*   Regularly review audit logs or use automated tools to analyze them for anomalies.
*   Commonly audited actions include resource creation/deletion/modification, RBAC changes, and Secret access.

By mastering these security fundamentals, you can significantly harden your Kubernetes cluster, making it more resilient against common threats and misconfigurations.

