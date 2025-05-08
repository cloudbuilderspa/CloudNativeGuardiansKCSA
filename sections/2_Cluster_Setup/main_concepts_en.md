---
layout: default
title: Main Concepts
parent: "2. Cluster Setup" 
nav_order: 1
permalink: /sections/cluster-setup/main-concepts/
---
# Main Concepts of Kubernetes Cluster Component Security

Understanding the security of each component within a Kubernetes cluster is fundamental for maintaining a robust and resilient cloud native environment. The Kubernetes and Cloud Native Security Associate (KCSA) exam emphasizes the security aspects of these core components. This document outlines the main security concepts related to setting up and securing your Kubernetes cluster components, based on the KCSA study guide.

## Control Plane Components

The control plane is the nerve center of Kubernetes, making global decisions about the cluster (e.g., scheduling) as well as detecting and responding to cluster events. Securing control plane components is paramount.

### API Server Security

*   **Role:** The API Server is the front-end for the Kubernetes control plane, exposing the Kubernetes API. It processes REST requests, validates them, and updates the corresponding objects in `etcd`. All administrative tasks and interactions with the cluster go through the API Server.

{% raw %}
<div class="mermaid">
graph LR
    subgraph "Clients"
        kubectl["kubectl (User/Admin)"]
    end

    subgraph "Control Plane"
        APIServer["Kubernetes API Server"]
        ControllerManager["Controller Manager"]
        Scheduler["Scheduler"]
        Etcd["etcd (Cluster Data Store)"]
    end

    subgraph "Worker Nodes"
        Kubelet1["Kubelet (Node 1)"]
        Kubelet2["Kubelet (Node N)"]
    end

    kubectl -- "TLS, AuthN/AuthZ" --> APIServer
    APIServer -- "TLS, AuthN/AuthZ" --> kubectl

    ControllerManager -- "TLS" --> APIServer
    APIServer -- "TLS" --> ControllerManager

    Scheduler -- "TLS" --> APIServer
    APIServer -- "TLS" --> Scheduler

    APIServer -- "mTLS (Client Cert AuthN)" --> Etcd

    Kubelet1 -- "TLS, AuthN/AuthZ" --> APIServer
    APIServer -- "TLS, AuthN/AuthZ" --> Kubelet1

    Kubelet2 -- "TLS, AuthN/AuthZ" --> APIServer
    APIServer -- "TLS, AuthN/AuthZ" --> Kubelet2

    classDef controlPlane fill:#D6EAF8,stroke:#333,stroke-width:2px;
    class APIServer,ControllerManager,Scheduler,Etcd controlPlane;

    classDef clients fill:#E8DAEF,stroke:#333,stroke-width:2px;
    class kubectl clients;

    classDef nodes fill:#D5F5E3,stroke:#333,stroke-width:2px;
    class Kubelet1,Kubelet2 nodes;
</div>
{% endraw %}

*   **Key Security Considerations &amp; Best Practices:**
    *   **Authentication:** Implement strong authentication mechanisms. Kubernetes supports various methods like client certificates, bearer tokens, and integrating with external identity providers (OIDC). Anonymous access should generally be disabled.
    *   **Authorization:** Use robust authorization models like Role-Based Access Control (RBAC) to ensure users and services only have the permissions necessary for their tasks (Principle of Least Privilege). Avoid overly permissive cluster-wide bindings.
    *   **Secure Communication (TLS):** Enforce TLS for all API Server communication (both to clients and between control plane components). Use strong ciphers and regularly rotate certificates.
    *   **Admission Control:** Utilize Admission Controllers to intercept requests to the API Server before objects are persisted in `etcd`. They can modify or reject requests based on custom policies (e.g., Pod Security Standards).
    *   **Audit Logging:** Enable and configure audit logging to record all requests made to the API Server. Regularly review audit logs for suspicious activity.
    *   **Network Exposure:** Limit network exposure of the API Server. If possible, do not expose it directly to the public internet. Use firewalls and network policies to restrict access.
    *   **Rate Limiting:** Implement rate limiting to protect the API Server from DoS attacks.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Allowing anonymous access or overly permissive RBAC roles.
    *   Weak or missing authentication/authorization.
    *   Using insecure ports or not enforcing TLS.
    *   Disabled or misconfigured audit logs.
    *   Lack of appropriate admission controllers.

### Controller Manager Security

*   **Role:** The Controller Manager runs controller processes. These controllers watch the shared state of the cluster through the API Server and make changes attempting to move the current state towards the desired state (e.g., ensuring the correct number of pods are running for a deployment).
*   **Key Security Considerations &amp; Best Practices:**
    *   **Least Privilege:** The Controller Manager's service account should have only the necessary permissions to manage resources.
    *   **Secure Communication:** Ensure it communicates with the API Server over a secure (TLS) channel.
    *   **Leader Election:** In HA setups, leader election for controller managers should be secured.
    *   **Resource Limits:** Apply resource quotas and limits to prevent controllers from consuming excessive cluster resources.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Overly permissive service account.
    *   Communication with API Server over insecure channels.

### Scheduler Security

*   **Role:** The Scheduler watches for newly created Pods that have no Node assigned, and for every Pod that the scheduler discovers, it becomes responsible for finding the best Node for that Pod to run on.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Least Privilege:** The Scheduler's service account should have only the necessary permissions (primarily to read pod/node information and bind pods to nodes).
    *   **Secure Communication:** Ensure it communicates with the API Server over a secure (TLS) channel.
    *   **Resource Limits:** Apply resource quotas and limits.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Overly permissive service account.
    *   Communication with API Server over insecure channels.

### Etcd Security

*   **Role:** `etcd` is a consistent and highly-available key-value store used as Kubernetes' backing store for all cluster data. It stores the configuration data, state, and metadata of the cluster.

{% raw %}
<div class="mermaid">
graph TD
    APIServer["Kubernetes API Server"]
    Etcd["etcd Cluster (Data Store)"]
    OtherComponents["Other K8s Components <br/> (kubectl, Controller Mgr, Scheduler, Kubelets)"]

    OtherComponents -- "API Requests (TLS, AuthN/AuthZ)" --> APIServer
    APIServer -- "Data CRUD Operations <br/> (mTLS: Client Cert AuthN <br/> TLS: Encryption in Transit)" --> Etcd
    Etcd -- "Data Encrypted at Rest" --- Etcd

    subgraph "Restricted Zone: Direct Etcd Access"
        direction LR
        DirectAccess["External/Unauthorized Access"]
        style DirectAccess fill:#FADBD8,stroke:#A93226
        DirectAccess --X|BLOCKED (Firewall/Network Policy)| Etcd
    end

    classDef controlPlane fill:#D6EAF8,stroke:#333,stroke-width:2px;
    class APIServer, Etcd controlPlane;

    classDef components fill:#E8DAEF,stroke:#333,stroke-width:2px;
    class OtherComponents components;

    linkStyle 2 stroke:green,stroke-width:1.5px;
    linkStyle 3 stroke:red,stroke-width:2px,stroke-dasharray:5,5;
</div>
{% endraw %}

*   **Key Security Considerations &amp; Best Practices:**
    *   **Access Control:** Restrict access to `etcd` to only the API Server. No other component should directly interact with `etcd`.
    *   **Encryption:**
        *   **In Transit:** Use TLS for communication between the API Server and `etcd`, and between `etcd` nodes themselves.
        *   **At Rest:** Enable encryption for `etcd` data at rest to protect sensitive information (like Secrets) stored on disk.
    *   **Network Isolation:** Isolate `etcd` members on a dedicated network if possible, and use firewalls to restrict access to `etcd` ports.
    *   **Regular Backups:** Implement a robust backup and restore strategy for `etcd`.
    *   **Separate Cluster:** For larger setups, consider running `etcd` as a cluster separate from the Kubernetes control plane nodes.
    *   **Strong Credentials:** Use strong client certificates for authentication between the API Server and `etcd`.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Unauthenticated or unencrypted access to `etcd`.
    *   Data at rest not encrypted.
    *   Exposed `etcd` ports to untrusted networks.
    *   Inadequate backup procedures.

## Node Components

Node components run on every worker node, maintaining running pods and providing the Kubernetes runtime environment.

### Kubelet Security

*   **Role:** The Kubelet is an agent that runs on each node in the cluster. It makes sure that containers are running in a Pod as specified by the control plane. It does not manage containers that were not created by Kubernetes.

{% raw %}
<div class="mermaid">
graph TD
    subgraph "Kubernetes Node"
        Kubelet["Kubelet"]
        ContainerRuntime["Container Runtime <br/> (e.g., containerd, CRI-O)"]
        KubeletAPI["Kubelet API Endpoint <br/> (Port 10250)"]
        style KubeletAPI fill:#EAECEE,stroke:#909497
        ReadOnlyPort["Read-Only API Endpoint <br/> (Port 10255 - Often disabled)"]
        style ReadOnlyPort fill:#FEF9E7,stroke:#F39C12

        Kubelet -- "CRI (gRPC)" --> ContainerRuntime
        Kubelet --- KubeletAPI
        Kubelet --- ReadOnlyPort
    end

    APIServer["Kubernetes API Server"]

    Kubelet -- "TLS, AuthN/AuthZ" --> APIServer
    APIServer -- "TLS, AuthN/AuthZ" --> Kubelet

    Client["Authorized Clients <br/> (e.g., Metrics Server, kubectl proxy)"] -- "HTTPS <br/> (Requires AuthN/AuthZ)" --> KubeletAPI
    UnauthClient["Potentially Unauthorized Access"] -.->|Usually Blocked or No AuthZ| ReadOnlyPort

    classDef controlPlane fill:#D6EAF8,stroke:#333,stroke-width:2px;
    class APIServer controlPlane;
    classDef nodeComponents fill:#D5F5E3,stroke:#333,stroke-width:2px;
    class Kubelet,ContainerRuntime nodeComponents;
    classDef client fill:#E8DAEF,stroke:#333,stroke-width:2px;
    class Client,UnauthClient client;

    linkStyle 3 stroke:red,stroke-dasharray:5,5;
</div>
{% endraw %}

*   **Key Security Considerations &amp; Best Practices:**
    *   **Authentication &amp; Authorization:**
        *   Secure the Kubelet API. Enable authentication (e.g., client certificates) and authorization (e.g., RBAC via webhook mode) for requests to the Kubelet API.
        *   Disable anonymous access to the Kubelet API.
    *   **Secure Communication:** Ensure Kubelet communicates with the API Server using TLS.
    *   **Read-Only Port:** Disable the read-only Kubelet port (port 10255) or ensure it's adequately firewalled as it can expose sensitive information.
    *   **Node Restriction:** Use the NodeRestriction admission controller to limit the API objects a Kubelet can modify.
    *   **Pod Security Standards:** Kubelet enforces Pod Security Standards via configured admission control.
    *   **Resource Management:** Configure Kubelet with appropriate resource limits (e.g., CPU, memory) for pods and system overhead.
    *   **Regular Updates:** Keep Kubelet and underlying node components updated to patch vulnerabilities.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Kubelet API exposed without authentication/authorization.
    *   Allowing anonymous access.
    *   Read-only port exposed to untrusted networks.
    *   Not using NodeRestriction admission controller.

### Container Runtime Security

*   **Role:** The Container Runtime is the software that is responsible for running containers (e.g., Docker, containerd, CRI-O). Kubelet interacts with the container runtime to manage the lifecycle of containers on a node.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Secure Configuration:** Harden the container runtime configuration (e.g., disable unnecessary features, configure secure defaults). Follow CIS Benchmarks for the specific runtime.
    *   **Principle of Least Privilege:** Run containers with the minimum required privileges. Avoid running containers as root if possible. Use security contexts.
    *   **Image Security:** Ensure only trusted and scanned container images are run. (Covered more in Image Security domain).
    *   **Kernel Security:** Utilize kernel security features (e.g., AppArmor, Seccomp, SELinux) to further isolate containers.
    *   **Regular Updates:** Keep the container runtime updated to patch known vulnerabilities.
    *   **Resource Isolation:** Ensure proper resource isolation between containers and between containers and the host.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Running containers with excessive privileges (e.g., as root, privileged mode).
    *   Using vulnerable or untrusted container images.
    *   Misconfigured runtime allowing container escapes.
    *   Outdated runtime versions.

### KubeProxy Security

*   **Role:** KubeProxy is a network proxy that runs on each node in your cluster, implementing part of the Kubernetes Service concept. It maintains network rules on nodes and performs connection forwarding.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Least Privilege:** KubeProxy's service account should have only the necessary permissions.
    *   **Secure Configuration:** Ensure KubeProxy is configured securely (e.g., correct mode like IPVS or iptables, appropriate logging).
    *   **Network Policies:** KubeProxy helps implement Network Policies by managing network rules on nodes, although Network Policies themselves are defined as API objects.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Misconfigured network rules leading to unintended network access.
    *   Overly permissive service account.

## Pod Security

*   **Role:** A Pod is the smallest, most basic deployable object in Kubernetes. A Pod represents a single instance of a running process in your cluster and can contain one or more containers, such as Docker containers. Pods share storage/network resources and a specification for how to run the containers.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Least Privilege:** Containers within Pods should run with the minimum necessary privileges. Avoid running as root.
    *   **Security Contexts:** Define `SecurityContext` for Pods and containers to control privilege and access control settings (e.g., `runAsUser`, `readOnlyRootFilesystem`, capabilities).
    *   **Pod Security Standards (PSS) / Pod Security Admission (PSA):** Enforce PSS (Baseline, Restricted) using PSA to set default security levels for Pods in namespaces.
    *   **Resource Limits &amp; Quotas:** Define resource requests and limits for Pods to prevent resource exhaustion and DoS.
    *   **Network Policies:** Use Network Policies to control traffic flow to and from Pods.
    *   **Secrets Management:** Securely inject sensitive data into Pods using Kubernetes Secrets rather than hardcoding in manifests or images.
    *   **Image Provenance:** Use trusted, scanned, and signed container images.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Running containers as root or with unnecessary capabilities.
    *   Lack of or poorly configured Security Contexts.
    *   Not enforcing Pod Security Standards.
    *   Missing resource limits, allowing for DoS.
    *   Overly permissive network access.

## Container Networking Security

*   **Role:** Container networking enables communication between containers, Pods, Services, and external networks. Kubernetes uses various CNI (Container Network Interface) plugins to implement networking.
*   **Key Security Considerations &amp; Best Practices:**
*   **Network Policies:** Implement Network Policies to segment network traffic within the cluster, enforcing a "default deny" posture where possible.

{% raw %}
<div class="mermaid">
graph TD
    subgraph "Before Network Policy"
        PodA1["Pod A (client)"] -->|TCP 80 Connection: ALLOWED| PodB1["Pod B (server)"]
    end

    subgraph "After 'Default Deny' Ingress Policy on Pod B"
        PodA2["Pod A (client)"] -.->|TCP 80 Connection: DENIED| PodB2["Pod B (server, app=backend)"]
        NetPol["NetworkPolicy <br/> selects app=backend <br/> spec: <br/>  ingress: [] <br/> (Denies All Ingress)"] -.-> PodB2
    end

    classDef pods fill:#D5F5E3,stroke:#333,stroke-width:2px;
    class PodA1,PodB1,PodA2,PodB2 pods;
    classDef netpol fill:#FFF3CD,stroke:#333,stroke-width:2px;
    class NetPol netpol;

    linkStyle 0 stroke:green,stroke-width:2px;
    linkStyle 1 stroke:red,stroke-width:2px,stroke-dasharray:5,5;
    linkStyle 2 stroke:#aaa,stroke-width:1px,stroke-dasharray:2,2;
</div>
{% endraw %}

*   **CNI Plugin Security:** Choose a CNI plugin that supports Network Policies and has a good security track record. Keep it updated.
    *   **Encryption:** Consider using a Service Mesh (like Istio, Linkerd) or CNI plugins that support transparent traffic encryption (e.g., WireGuard based) for inter-Pod communication if sensitive data is involved.
    *   **Network Segmentation:** Logically segment your cluster network using Namespaces and Network Policies.
    *   **Egress Control:** Control outbound traffic from Pods to limit the blast radius of a compromised Pod.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Lack of Network Policies, leading to a flat network where all Pods can communicate.
    *   Vulnerable or misconfigured CNI plugins.
    *   Unencrypted sensitive traffic between Pods.

## Client Security

*   **Role:** Client security refers to securing the tools and methods used by users and automated systems to interact with the Kubernetes API Server. This primarily involves `kubectl` and client libraries/SDKs.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Kubeconfig Files:** Protect `kubeconfig` files as they contain credentials and API server details. Apply strict file permissions. Avoid embedding credentials directly in scripts; use service accounts or identity federation where possible.
    *   **Authentication:** Use strong authentication methods for clients (e.g., OIDC, client certificates). Avoid using long-lived static tokens or basic authentication.
    *   **RBAC:** Ensure users and service accounts associated with clients have the minimum necessary permissions via RBAC.
    *   **Client Tools:** Keep `kubectl` and other client tools updated.
    *   **Audit Client Activity:** Monitor API server audit logs to track client interactions.
    *   **Short-lived Credentials:** Use short-lived credentials where possible, especially for automated systems.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Exposed or poorly permissioned `kubeconfig` files.
    *   Use of shared, highly privileged accounts.
    *   Outdated client tools with known vulnerabilities.

## Storage Security

*   **Role:** Kubernetes provides various storage options (volumes) for Pods, including persistent storage through PersistentVolume (PV) and PersistentVolumeClaim (PVC) objects, and ephemeral storage.
*   **Key Security Considerations &amp; Best Practices:**
    *   **Access Control:**
        *   Use RBAC to control who can create and manage PVs and PVCs.
        *   Configure file system permissions within containers appropriately.
        *   For network-attached storage, use underlying storage system's access control mechanisms.
    *   **Encryption:**
        *   **At Rest:** Ensure data stored in PVs is encrypted at rest by the underlying storage provider or through solutions like dm-crypt.
        *   **In Transit:** If using network storage, ensure data is encrypted in transit between nodes and the storage system.
    *   **Secrets for Storage:** When storage systems require credentials, use Kubernetes Secrets to store and mount them securely, rather than hardcoding in Pod specs.
    *   **StorageClasses:** Define `StorageClass` objects to manage different types of storage and their properties, including encryption.
    *   **Volume Types:** Choose volume types appropriate for the sensitivity of the data (e.g., `emptyDir` is ephemeral, PVs are for persistent data).
    *   **Regular Backups:** Ensure persistent data is regularly backed up.
*   **Common Vulnerabilities/Misconfigurations:**
    *   Unencrypted sensitive data at rest or in transit.
    *   Overly permissive access to storage resources or data.
    *   Insecure handling of storage credentials.
    *   Lack of backups for critical persistent data.

By focusing on these aspects for each component, administrators can significantly improve the security posture of their Kubernetes clusters, aligning with the foundational knowledge required for the KCSA certification.

