# Lab Guide: Kubernetes Threat Model and System Hardening

This lab guide provides exercises to help you understand and identify aspects of the Kubernetes Threat Model and system hardening considerations. The focus is on inspection and analysis using `kubectl`, rather than simulating attacks. These exercises are designed for a KCSA-level understanding.

**Note:** Ensure you have a namespace for testing (e.g., `threat-lab-ns`) or create one: `kubectl create namespace threat-lab-ns`. Remember to clean up resources after completing the labs.

## Exercise 1: Identifying Risky Pod Configurations

**Objective:** To identify Pod configurations that could pose security risks.

**Instructions:**

1.  **Review a Pod Manifest with a Risky `hostPath` Volume:**
    *   Consider the following manifest (`risky-hostpath-pod.yaml` - do not apply yet, just review):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: risky-hostpath-pod
          namespace: threat-lab-ns # Assuming this namespace exists
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
            volumeMounts:
            - name: docker-socket
              mountPath: /var/run/docker.sock
          volumes:
          - name: docker-socket
            hostPath:
              path: /var/run/docker.sock # Mounting Docker socket
        ```
    *   **Discussion:**
        *   What is the potential threat if this Pod is deployed and compromised? (Attacker could control Docker daemon on the node, leading to node compromise).
        *   Which Pod Security Standard (PSS) level would likely prevent this? (`Baseline` and `Restricted` should prevent this).
    *   **Security Note:** Mounting sensitive host paths like the Docker socket, `/etc`, or `/` is extremely dangerous.

2.  **Review a Pod Manifest with `privileged: true`:**
    *   Consider (`privileged-example-pod.yaml` - review only):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: privileged-example-pod
          namespace: threat-lab-ns
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
            securityContext:
              privileged: true
        ```
    *   **Discussion:**
        *   What capabilities does a privileged Pod have? (Nearly all capabilities of the host, bypasses many security mechanisms).
        *   Why is this a significant risk? (Easy node compromise if the container is breached).
    *   **Security Note:** Avoid privileged Pods unless absolutely necessary for system-level tasks and only with extreme caution and other compensating controls.

3.  **Review a Pod Manifest with Weak `securityContext`:**
    *   Consider (`weak-sctx-pod.yaml` - review only):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: weak-sctx-pod
          namespace: threat-lab-ns
        spec:
          containers:
          - name: main
            image: nginx # Runs as root by default
            command: ["sleep", "3600"]
            # No securityContext specified, or one that allows:
            # securityContext:
            #   runAsUser: 0 # Explicitly running as root
            #   allowPrivilegeEscalation: true
        ```
    *   **Discussion:**
        *   What are the risks of running as root in a container by default? (Broader permissions if container is compromised).
        *   What does `allowPrivilegeEscalation: true` (default if not set) imply? (A process can gain more privileges than its parent).
    *   **Security Note:** Always define a `securityContext` to enforce least privilege: `runAsNonRoot: true`, `runAsUser` (non-zero), `allowPrivilegeEscalation: false`, drop unnecessary `capabilities`.

## Exercise 2: Analyzing RBAC for Potential Privilege Escalation

**Objective:** To identify RBAC configurations that could be abused for privilege escalation (without performing the escalation).

**Instructions:**

1.  **Create a Test Namespace, ServiceAccount, Role, and RoleBinding:**
    ```bash
    kubectl create namespace rbac-escalation-lab
    kubectl create serviceaccount privesc-sa -n rbac-escalation-lab
    ```
    *   Create `escalation-role.yaml`:
        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: rbac-escalation-lab
          name: escalation-potential-role
        rules:
        # Rule 1: Permission to create rolebindings in its own namespace
        - apiGroups: ["rbac.authorization.k8s.io"]
          resources: ["rolebindings"]
          verbs: ["create"]
        # Rule 2: Permission to use the 'passimpersonate' verb on a specific user (e.g., a privileged user)
        # For this lab, we'll just list it; binding passimpersonate is more complex to set up safely.
        # - apiGroups: [""]
        #   resources: ["users"]
        #   verbs: ["impersonate"]
        #   resourceNames: ["admin-user"] # Example user
        # Rule 3: Permission to create pods (could be used to mount sensitive info or use privileged SA)
        - apiGroups: [""]
          resources: ["pods"]
          verbs: ["create", "list"]
        ```
    *   Apply the Role: `kubectl apply -f escalation-role.yaml`
    *   Bind the ServiceAccount to this Role:
        ```bash
        kubectl create rolebinding privesc-sa-binding \
          --role=escalation-potential-role \
          --serviceaccount=rbac-escalation-lab:privesc-sa \
          -n rbac-escalation-lab
        ```

2.  **Use `kubectl auth can-i` to Check Permissions:**
    ```bash
    # Can the SA create rolebindings in its namespace?
    kubectl auth can-i create rolebindings --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab

    # Can the SA create pods in its namespace?
    kubectl auth can-i create pods --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab
    ```

3.  **Discussion:**
    *   If `privesc-sa` can create `rolebindings` in its namespace, how could it escalate its privileges? (It could bind itself, or another SA it controls, to a more powerful Role within that namespace, potentially up to `admin` for that namespace).
    *   If `privesc-sa` can create Pods, how might this be abused if not further restricted by PSS/PSA? (Could create a Pod that uses a very privileged SA from *another* namespace if that SA is not restricted, or a Pod that mounts hostPaths, etc.)
    *   If an SA had `passimpersonate` for a `cluster-admin` user, what would that allow? (The SA could act as `cluster-admin`, gaining full cluster control).
    *   **Security Note:** Permissions like `create rolebindings`, `create clusterrolebindings`, `passimpersonate`, or broad Pod creation rights are highly sensitive and should be strictly controlled.

4.  **Clean up:**
    ```bash
    kubectl delete namespace rbac-escalation-lab
    rm escalation-role.yaml
    ```

## Exercise 3: Exploring Trust Boundaries and Network Segmentation

**Objective:** To observe default network behavior and the effect of Network Policies.

**Instructions:**

1.  **Create Two Test Namespaces and Deploy Pods:**
    ```bash
    kubectl create namespace netpol-ns1
    kubectl create namespace netpol-ns2

    kubectl run web-ns1 --image=nginx -n netpol-ns1 --labels=app=web
    kubectl run web-ns2 --image=nginx -n netpol-ns2 --labels=app=web
    ```
    *   Wait for Pods to be running:
        ```bash
        kubectl get pods -n netpol-ns1 -w
        kubectl get pods -n netpol-ns2 -w
        ```

2.  **Attempt Communication Between Pods in Different Namespaces:**
    *   Get IP of `web-ns2`: `POD_NS2_IP=$(kubectl get pod web-ns2 -n netpol-ns2 -o jsonpath='{.status.podIP}')`
    *   Exec into `web-ns1` and try to curl `web-ns2`:
        ```bash
        kubectl exec -it web-ns1 -n netpol-ns1 -- curl --connect-timeout 2 -I $POD_NS2_IP
        ```
    *   **Expected Outcome:** By default, communication should succeed. This shows that namespaces by themselves are not network isolation boundaries.
    *   **Security Note:** This illustrates a flat network model without Network Policies.

3.  **Apply a Default-Deny Ingress Policy to `netpol-ns2`:**
    *   Create `deny-all-ingress-ns2.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-all-ingress
          namespace: netpol-ns2
        spec:
          podSelector: {} # Apply to all pods in netpol-ns2
          policyTypes:
          - Ingress
        ```
    *   Apply: `kubectl apply -f deny-all-ingress-ns2.yaml`

4.  **Re-test Communication from `web-ns1` to `web-ns2`:**
    ```bash
    kubectl exec -it web-ns1 -n netpol-ns1 -- curl --connect-timeout 2 -I $POD_NS2_IP
    ```
    *   **Expected Outcome:** Communication should now **fail** (timeout).
    *   **Discussion:** How does this demonstrate a trust boundary enforced by Network Policy? (Traffic from `netpol-ns1` is no longer trusted by default to enter `netpol-ns2`). This helps mitigate lateral movement.

5.  **Clean up:**
    ```bash
    kubectl delete namespace netpol-ns1
    kubectl delete namespace netpol-ns2
    rm deny-all-ingress-ns2.yaml
    ```

## Exercise 4: Simulating Sensitive Data Access Scenarios (Conceptual)

**Objective:** To understand how RBAC controls access to Secrets and the importance of etcd encryption.

**Instructions:**

1.  **Create a Namespace and a Secret:**
    ```bash
    kubectl create namespace secret-access-lab
    kubectl create secret generic mysecret -n secret-access-lab --from-literal=secretdata='veryconfidential'
    ```

2.  **Create Two ServiceAccounts:**
    ```bash
    kubectl create serviceaccount sa-no-access -n secret-access-lab
    kubectl create serviceaccount sa-with-access -n secret-access-lab
    ```

3.  **Create a Role and RoleBinding for `sa-with-access` to read `mysecret`:**
    *   `secret-reader-role.yaml`:
        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: secret-access-lab
          name: secret-reader
        rules:
        - apiGroups: [""]
          resources: ["secrets"]
          resourceNames: ["mysecret"] # Specific secret
          verbs: ["get"]
        ```
    *   Apply Role: `kubectl apply -f secret-reader-role.yaml`
    *   Bind `sa-with-access`:
        ```bash
        kubectl create rolebinding sa-with-access-secret-reader-binding \
          --role=secret-reader \
          --serviceaccount=secret-access-lab:sa-with-access \
          -n secret-access-lab
        ```

4.  **Conceptual Analysis of Access:**
    *   **Pod with `sa-no-access`:**
        *   If you deployed a Pod using `sa-no-access`, and it tried to use its token to `kubectl get secret mysecret -n secret-access-lab`, what would happen? (It would be denied by RBAC).
        *   If it tried to mount `mysecret` as a volume, what would happen? (The Kubelet, acting on behalf of the Pod via its SA token, would likely be denied permission by the API server to fetch the secret for mounting, so the Pod might fail to start).
    *   **Pod with `sa-with-access`:**
        *   If you deployed a Pod using `sa-with-access` and mounted `mysecret` as a volume, it would succeed. The Kubelet (using the SA's token) would be authorized to fetch the Secret.
        *   The Pod could then read the secret data from the mounted files.

5.  **Discussion on Etcd Encryption:**
    *   Where are Kubernetes Secrets stored? (In `etcd`).
    *   By default, are they encrypted in `etcd`? (No, only base64 encoded).
    *   Why is enabling encryption at rest for `etcd` critical for protecting Secrets? (It protects the Secret data even if an attacker gains access to `etcd` backups or the raw `etcd` data files).
    *   **Security Note:** RBAC controls *API access* to Secrets. Etcd encryption protects Secrets *at rest*. Both are needed.

6.  **Clean up:**
    ```bash
    kubectl delete namespace secret-access-lab
    rm secret-reader-role.yaml
    ```

## Exercise 5: Recognizing Denial of Service Vectors (Conceptual)

**Objective:** To identify configurations or scenarios that could lead to DoS.

**Instructions:**

1.  **Review a Pod Manifest with No Resource Limits:**
    *   Consider (`no-limits-pod.yaml` - review only):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: no-limits-pod
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "while true; do echo consuming...; done"] # Example of a busy loop
            # No resources: { limits: ..., requests: ...} defined
        ```
    *   **Discussion:**
        *   What could happen if many such Pods are deployed on a node without resource limits? (CPU/memory exhaustion on the node, affecting other Pods and Kubelet stability - a "noisy neighbor" DoS).
        *   How do `LimitRange` and `ResourceQuota` objects help mitigate this? (`LimitRange` sets default limits/requests for Pods in a namespace if not specified; `ResourceQuota` sets overall resource consumption limits for a namespace).
    *   **Security Note:** Always set resource requests and limits for your workloads.

2.  **Discuss API Server Overload (Conceptual):**
    *   **Scenario:** Imagine a script (or a compromised component) making thousands of API requests per second to the API Server.
    *   **Impact:** This could overwhelm the API Server, making it slow or unresponsive for legitimate users and control plane components.
    *   **Mitigation:**
        *   API Server has built-in rate limiting (though defaults might need tuning for very large clusters or specific abuse cases).
        *   Proper authentication and authorization to prevent unauthorized clients from making excessive requests.
        *   Monitoring API Server performance and request latencies.
    *   **Security Note:** Protecting the API Server from DoS is crucial for cluster availability.

## Exercise 6: Considering Persistence Techniques (Conceptual)

**Objective:** To think about how attackers might achieve persistence in a Kubernetes cluster.

**Instructions:**

1.  **Review a CronJob Manifest:**
    *   Consider (`example-cronjob.yaml` - review only):
        ```yaml
        apiVersion: batch/v1
        kind: CronJob
        metadata:
          name: example-cronjob
        spec:
          schedule: "*/5 * * * *" # Every 5 minutes
          jobTemplate:
            spec:
              template:
                spec:
                  restartPolicy: OnFailure
                  containers:
                  - name: main
                    image: busybox
                    command: ["echo", "Hello from CronJob"]
        ```
    *   **Discussion:**
        *   If an attacker has RBAC permissions to create CronJobs in a namespace, how could they use this for persistence? (They could schedule a CronJob to run a Pod with a malicious image or command periodically, e.g., to re-establish a reverse shell or exfiltrate data).
    *   **Mitigation:** Restrict permissions to create/manage CronJobs using RBAC. Monitor CronJob creation.

2.  **Discuss Backdoored Images in Deployments:**
    *   **Scenario:** An attacker manages to get a backdoored container image (e.g., containing a reverse shell binary) into a Deployment's Pod template.
    *   **Persistence:** Every time the Deployment scales up or a Pod is restarted, a new Pod with the backdoored image will be created, potentially re-establishing attacker access.
    *   **Mitigation:**
        *   Strong image security practices (scanning, trusted registries, image signing - covered in Supply Chain Security).
        *   RBAC to restrict who can modify Deployments.
        *   GitOps with manifest validation and review before applying changes.
    *   **Security Note:** Persistence through workload controllers like Deployments or DaemonSets is effective for attackers because Kubernetes actively tries to keep these workloads running.

**Cleanup Note:** Delete any namespaces or test resources created if not already done in individual exercises.

