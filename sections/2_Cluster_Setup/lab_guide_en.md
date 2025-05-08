# Lab Guide: Kubernetes Cluster Component Security

This lab guide provides practical exercises to help you understand and apply security concepts related to Kubernetes cluster components. These exercises are designed for a KCSA-level understanding and assume you have `kubectl` access to a Kubernetes cluster (like Minikube, Kind, or a cloud-managed cluster where you have appropriate permissions).

**Note:** Some commands, especially those inspecting control plane component configurations, might require node access or specific configurations that vary between Kubernetes distributions and managed services. Adapt commands as necessary for your environment.

## Exercise 1: API Server Security Inspection

**Objective:** To inspect key security configurations of the Kubernetes API Server.

**Instructions:**

1.  **Check API Server Authentication and Authorization Flags:**
    *   If you have access to the control plane node(s), you can inspect the API Server manifest file. For Minikube, you can SSH into the Minikube VM:
        ```bash
        minikube ssh
        sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml
        ```
    *   Look for flags like:
        *   `--anonymous-auth`: Should ideally be `false`.
        *   `--authorization-mode`: Should include `Node,RBAC` (or other authorizers as appropriate).
        *   `--client-ca-file`: Specifies the CA for client certificate authentication.
        *   `--tls-cert-file` and `--tls-private-key-file`: Specifies the server certificate and private key for TLS.
    *   **Expected Outcome:** You should be able to identify how authentication and authorization are configured.
    *   **Security Note:** These flags define fundamental security settings. Misconfiguration can lead to unauthorized access.

2.  **Inspect RBAC Roles and ClusterRoles:**
    *   List all ClusterRoles:
        ```bash
        kubectl get clusterroles
        ```
    *   Describe a potentially overly permissive role like `cluster-admin`:
        ```bash
        kubectl describe clusterrole cluster-admin
        ```
    *   List all RoleBindings and ClusterRoleBindings:
        ```bash
        kubectl get rolebindings --all-namespaces
        kubectl get clusterrolebindings
        ```
    *   **Expected Outcome:** Understanding of how roles and bindings grant permissions. You might identify subjects (users, groups, service accounts) bound to powerful roles.
    *   **Security Note:** RBAC is critical. Regularly audit roles and bindings to ensure the principle of least privilege is maintained.

3.  **Check for Anonymous Authentication Status (Indirectly):**
    *   Try to access a common API endpoint without any credentials. If anonymous auth is disabled (which is the default and recommended), you should receive an unauthorized error.
        ```bash
        # This command will likely fail if run from outside the cluster without a proxy
        # or proper kubeconfig. If you have curl within a pod:
        # curl -k https://kubernetes.default.svc/api/v1/pods
        # A more direct test would be to configure kubectl with no user and try.
        # For this lab, focus on the --anonymous-auth flag inspection.
        ```
    *   **Expected Outcome:** Confirmation (primarily via flag inspection) that anonymous access is disabled.
    *   **Security Note:** Anonymous access provides an unauthenticated entry point and should almost always be disabled.

## Exercise 2: Kubelet Security

**Objective:** To understand Kubelet API security and its exposure.

**Instructions:**

1.  **Attempt to Access Kubelet API (Port 10250):**
    *   First, get the IP address of one of your nodes:
        ```bash
        kubectl get nodes -o wide
        ```
    *   If you can exec into a pod running on that node, or if you have network access to the node's port 10250, try to access the Kubelet's `/pods` endpoint. Replace `NODE_IP` with the actual IP.
        ```bash
        # Example from within a pod that can reach the node:
        # curl -k https://NODE_IP:10250/pods
        ```
        Or, using `kubectl proxy` and `kubectl get --raw`:
        ```bash
        kubectl proxy &
        # Get a node name
        NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
        kubectl get --raw "/api/v1/nodes/${NODE_NAME}/proxy/pods"
        # Kill the proxy: fg then Ctrl+C
        ```
    *   **Expected Outcome:** If Kubelet authentication/authorization is enabled (default), you should get an unauthorized error or be prompted for credentials if accessing directly. If using `kubectl get --raw` through the proxy, it uses your `kubectl` credentials, which are likely authorized. This demonstrates secure access.
    *   **Security Note:** The Kubelet API (10250) must be protected by authentication and authorization.

2.  **Discussing the Read-Only Port (10255):**
    *   The Kubelet *used to* expose a read-only port (10255) for metrics and status, which did not require authentication. This is generally disabled or restricted in modern Kubernetes versions.
    *   To check if it's active on a node you have access to, you could try:
        ```bash
        # From a machine that can reach NODE_IP or from within a pod on that node:
        # curl http://NODE_IP:10255/pods
        ```
    *   **Discussion:** Why is an unauthenticated read-only port a security risk? (Information disclosure about workloads and node configuration).
    *   **Security Note:** Ensure port 10255 is disabled or firewalled if not needed and if it exists in your version.

## Exercise 3: Etcd Security (Conceptual/Verification)

**Objective:** To understand how `etcd` security is typically configured. Direct `etcd` access is usually restricted and not available to typical users.

**Instructions:**

1.  **Verify Etcd Communication over TLS (API Server Configuration):**
    *   Inspect your API Server manifest (as in Exercise 1.1).
    *   Look for flags related to `etcd` communication:
        *   `--etcd-servers`: Should list `etcd` server URLs using `https://`.
        *   `--etcd-cafile`: CA certificate to verify `etcd` server certificates.
        *   `--etcd-certfile` and `--etcd-keyfile`: Client certificate and key for the API Server to authenticate to `etcd`.
    *   **Expected Outcome:** Confirmation that the API Server is configured to communicate with `etcd` over TLS using mutual authentication.
    *   **Security Note:** Encrypting communication between the API Server and `etcd` is crucial to protect cluster state data in transit.

2.  **Review Etcd Encryption-at-Rest Settings (API Server Configuration):**
    *   In the API Server manifest, look for the `--encryption-provider-config` flag.
    *   If this flag is present and configured, it means encryption at rest for `etcd` data (especially Secrets) is enabled. The referenced configuration file would detail the encryption providers (e.g., `aescbc`, `kms`).
    *   **Expected Outcome:** Understanding of whether and how encryption at rest is configured for `etcd`. In many managed Kubernetes services, this is handled by the provider.
    *   **Security Note:** Encrypting sensitive data like Secrets at rest in `etcd` is a critical security measure.

## Exercise 4: Pod Security Context

**Objective:** To apply and observe the effects of `SecurityContext` settings on Pods.

**Instructions:**

1.  **Deploy a Pod with a Restrictive `SecurityContext`:**
    *   Create a YAML file (e.g., `restricted-pod.yaml`):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: restricted-pod
        spec:
          securityContext:
            runAsUser: 1000
            runAsGroup: 3000
            fsGroup: 2000
            runAsNonRoot: true
          containers:
          - name: main-container
            image: alpine
            command: ["sh", "-c", "sleep 1h && id && ls -ld /data"]
            securityContext:
              readOnlyRootFilesystem: true
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                - "ALL"
            volumeMounts:
            - name: data-vol
              mountPath: /data
          volumes:
          - name: data-vol
            emptyDir: {}
        ```
    *   Apply the manifest: `kubectl apply -f restricted-pod.yaml`
    *   Check the Pod status and logs:
        ```bash
        kubectl get pod restricted-pod
        kubectl logs restricted-pod
        # After some time, or exec into it if it runs long enough
        kubectl exec -it restricted-pod -- sh
        # Inside the pod, try:
        # id
        # touch /test.txt (should fail)
        # touch /data/test-data.txt (should succeed, check fsGroup permissions later)
        ```
    *   **Expected Outcome:** The Pod should run successfully. Commands inside the container should reflect the `runAsUser` and `runAsGroup`. The root filesystem should be read-only.
    *   **Security Note:** `SecurityContext` is vital for enforcing the principle of least privilege for workloads.

2.  **Observe a Pod Failing Due to `runAsNonRoot` (if image runs as root):**
    *   Create `violating-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: violating-pod
        spec:
          securityContext:
            runAsNonRoot: true # Enforce non-root
          containers:
          - name: main-container
            image: nginx # Nginx official image runs as root by default
            command: ["sleep", "3600"]
        ```
    *   Apply: `kubectl apply -f violating-pod.yaml`
    *   Check status: `kubectl get pod violating-pod -w`
    *   Describe the pod for events: `kubectl describe pod violating-pod`
    *   **Expected Outcome:** The Pod should fail to start (e.g., `CreateContainerError` or similar status). The events should indicate a security context constraint violation because the image tries to run as root.
    *   **Security Note:** This demonstrates how `runAsNonRoot` can prevent images from running as root. This often requires images to be built to support running as non-root users.

## Exercise 5: Service Account Token Security

**Objective:** To understand and manage Service Account token usage in Pods.

**Instructions:**

1.  **Inspect Default Service Account Token in a Pod:**
    *   Deploy a simple Pod: `kubectl run test-pod --image=busybox --restart=Never -- sh -c "sleep 3600"`
    *   Exec into the Pod: `kubectl exec -it test-pod -- sh`
    *   Inside the Pod, inspect the default token:
        ```sh
        ls /var/run/secrets/kubernetes.io/serviceaccount/
        cat /var/run/secrets/kubernetes.io/serviceaccount/token
        ```
    *   **Expected Outcome:** You will see the `token`, `ca.crt`, and `namespace` files. The token is a JWT.
    *   **Security Note:** By default, Pods get a token for the `default` service account in their namespace. This token might have more permissions than necessary.

2.  **Create a Pod That Does NOT Automount the Service Account Token:**
    *   Create `no-token-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: no-token-pod
        spec:
          automountServiceAccountToken: false
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
        ```
    *   Apply: `kubectl apply -f no-token-pod.yaml`
    *   Exec into `no-token-pod` and check:
        ```bash
        kubectl exec -it no-token-pod -- sh
        ls /var/run/secrets/kubernetes.io/serviceaccount/
        ```
    *   **Expected Outcome:** The directory `/var/run/secrets/kubernetes.io/serviceaccount/` should not exist or be empty.
    *   **Security Note:** If a Pod doesn't need to interact with the API Server, disable token automounting.

3.  **Use a Dedicated Service Account with Minimal Permissions:**
    *   Create a ServiceAccount: `kubectl create serviceaccount my-app-sa`
    *   Create a Role (e.g., allowing only to view pods in the default namespace):
        ```yaml
        # my-role.yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: default
          name: pod-viewer-role
        rules:
        - apiGroups: [""] # "" indicates the core API group
          resources: ["pods"]
          verbs: ["get", "watch", "list"]
        ```
        `kubectl apply -f my-role.yaml`
    *   Create a RoleBinding:
        `kubectl create rolebinding pod-viewer-binding --role=pod-viewer-role --serviceaccount=default:my-app-sa`
    *   Deploy a Pod using this ServiceAccount:
        ```yaml
        # sa-pod.yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: sa-pod
        spec:
          serviceAccountName: my-app-sa
          containers:
          - name: main
            image: appropriate/curl # An image with curl
            command: ["sleep", "3600"] # Keep it running to exec
        ```
        `kubectl apply -f sa-pod.yaml`
    *   Exec into `sa-pod` and try to use its token to list pods (this requires `curl` and `jq` in the image, or you can extract the token and test from outside):
        ```bash
        # kubectl exec -it sa-pod -- sh
        # TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
        # CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        # curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
        ```
    *   **Expected Outcome:** The Pod should be able to list pods using its token. If it tried other actions, it would be denied.
    *   **Security Note:** Always create dedicated service accounts with the least privilege necessary.

## Exercise 6: Container Runtime Security Profiles (Conceptual/Verification)

**Objective:** To understand how to apply basic seccomp profiles.

**Instructions:**

1.  **Deploy a Pod with `RuntimeDefault` Seccomp Profile:**
    *   Create `seccomp-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: seccomp-default-pod
        spec:
          securityContext:
            seccompProfile:
              type: RuntimeDefault
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "echo 'Running with RuntimeDefault seccomp profile'; sleep 3600"]
        ```
    *   Apply: `kubectl apply -f seccomp-pod.yaml`
    *   Check status: `kubectl get pod seccomp-default-pod`
    *   **Expected Outcome:** The Pod should run successfully. The `RuntimeDefault` profile is generally safe and recommended as a baseline.
    *   **Security Note:** `RuntimeDefault` uses the seccomp profile defined by the container runtime, which is typically a good starting point for syscall filtering. For higher security, custom (more restrictive) profiles might be needed.

2.  **Discussing AppArmor/SELinux (Conceptual):**
    *   **Verification (High-Level):**
        *   AppArmor: On a node, you might check `sudo aa-status` to see loaded AppArmor profiles.
        *   SELinux: On a node, `getenforce` shows the SELinux mode.
    *   **Interaction with Pods:** Kubernetes allows specifying AppArmor profiles via annotations (`container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>`) or SELinux options in the `securityContext.seLinuxOptions`.
    *   **Discussion:** Why are these MAC systems important? (They provide an additional layer of defense by restricting what processes can do, even if they are running as root or have some capabilities.)
    *   **Security Note:** Implementing and managing AppArmor/SELinux profiles can be complex but offers strong hardening. For KCSA, understanding their purpose and how Kubernetes can leverage them is important.

These exercises provide a starting point for exploring Kubernetes cluster component security. Remember to clean up any resources you create after completing the labs (e.g., `kubectl delete pod test-pod`).

