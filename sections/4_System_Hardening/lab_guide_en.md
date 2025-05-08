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

**✨ Prediction Point ✨**
*Before even considering applying this manifest, what are the immediate red flags regarding `hostPath` and `/var/run/docker.sock`?*
    *   **Discussion:**
        *   What is the potential threat if this Pod is deployed and compromised? (Attacker could control Docker daemon on the node, leading to node compromise).
        *   Which Pod Security Standard (PSS) level would likely prevent this? (`Baseline` and `Restricted` should prevent this).
    *   **Security Note:** Mounting sensitive host paths like the Docker socket, `/etc`, or `/` is extremely dangerous.

**✅ Verification Point ✅**
*Explain in your own words why mounting the Docker socket is a high-severity risk. What specific capabilities could an attacker gain?*

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

**🚀 Challenge Task 🚀**
*Modify the `weak-sctx-pod.yaml` (conceptually, or by creating the file) to make it adhere to the `restricted` Pod Security Standard as much as possible for a simple Nginx container. List the `securityContext` fields you would add or change at both the Pod and container level, if applicable.*

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

**✨ Prediction Point ✨**
*Given the `escalation-potential-role` grants `create rolebindings` and `create pods`, what is the most direct way the `privesc-sa` could try to elevate its privileges within the `rbac-escalation-lab` namespace?*

2.  **Use `kubectl auth can-i` to Check Permissions:**
    ```bash
    # Can the SA create rolebindings in its namespace?
    kubectl auth can-i create rolebindings --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab

    # Can the SA create pods in its namespace?
    kubectl auth can-i create pods --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab
    ```

**✅ Verification Point ✅**
*Confirm the `can-i` checks align with the permissions granted in `escalation-role.yaml`. If an attacker controls `privesc-sa`, which of these two permissions (`create rolebindings` vs `create pods`) offers a more versatile path to privilege escalation within the namespace and why?*

3.  **Discussion:**
    *   If `privesc-sa` can create `rolebindings` in its namespace, how could it escalate its privileges? (It could bind itself, or another SA it controls, to a more powerful Role within that namespace, potentially up to `admin` for that namespace).
    *   If `privesc-sa` can create Pods, how might this be abused if not further restricted by PSS/PSA? (Could create a Pod that uses a very privileged SA from *another* namespace if that SA is not restricted, or a Pod that mounts hostPaths, etc.)
    *   If an SA had `passimpersonate` for a `cluster-admin` user, what would that allow? (The SA could act as `cluster-admin`, gaining full cluster control).
    *   **Security Note:** Permissions like `create rolebindings`, `create clusterrolebindings`, `passimpersonate`, or broad Pod creation rights are highly sensitive and should be strictly controlled.

**🚀 Challenge Task 🚀**
*Describe a specific `Role` (provide the YAML) that, if `privesc-sa` could bind itself to via a new `RoleBinding`, would grant it administrative control over *all* resources (except other RBAC resources) within the `rbac-escalation-lab` namespace. What is the key `apiGroups`, `resources`, and `verbs` combination for this?*

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

**✨ Prediction Point ✨**
*You've just confirmed `web-ns1` can reach `web-ns2`. If you apply a `default-deny` ingress policy to `netpol-ns2` (as in the next step), will `web-ns1` still be able to reach `web-ns2`? Why or why not?*
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

**✅ Verification Point ✅**
*After applying the `default-deny-all-ingress` policy to `netpol-ns2`, re-run the `curl` command from `web-ns1` to `web-ns2`'s IP. Did it fail as expected? What does this tell you about the default network posture once a `NetworkPolicy` targeting pods is introduced in a namespace?*

4.  **Re-test Communication from `web-ns1` to `web-ns2`:**
    ```bash
    kubectl exec -it web-ns1 -n netpol-ns1 -- curl --connect-timeout 2 -I $POD_NS2_IP
    ```
    *   **Expected Outcome:** Communication should now **fail** (timeout).
    *   **Discussion:** How does this demonstrate a trust boundary enforced by Network Policy? (Traffic from `netpol-ns1` is no longer trusted by default to enter `netpol-ns2`). This helps mitigate lateral movement.

**🚀 Challenge Task 🚀**
*Create a new `NetworkPolicy` manifest that would specifically allow ingress to `web-ns2` (labeled `app=web`) ONLY from pods in `netpol-ns1` that are also labeled `app=web`, on TCP port 80. All other ingress to `web-ns2` should remain denied by the existing `default-deny-all-ingress` policy.*

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

**✨ Prediction Point ✨**
*If a Pod uses `sa-no-access`, do you expect it to be able to (a) mount `mysecret` as a volume, or (b) read `mysecret` using `kubectl` with its service account token? What about a Pod using `sa-with-access`?*

4.  **Conceptual Analysis of Access:**
    *   **Pod with `sa-no-access`:**
        *   If you deployed a Pod using `sa-no-access`, and it tried to use its token to `kubectl get secret mysecret -n secret-access-lab`, what would happen? (It would be denied by RBAC).
        *   If it tried to mount `mysecret` as a volume, what would happen? (The Kubelet, acting on behalf of the Pod via its SA token, would likely be denied permission by the API server to fetch the secret for mounting, so the Pod might fail to start).
    *   **Pod with `sa-with-access`:**
        *   If you deployed a Pod using `sa-with-access` and mounted `mysecret` as a volume, it would succeed. The Kubelet (using the SA's token) would be authorized to fetch the Secret.
        *   The Pod could then read the secret data from the mounted files.

**✅ Verification Point ✅**
*Considering the RBAC setup, explain why a Pod with `sa-with-access` can successfully mount and read `mysecret`, while a Pod with `sa-no-access` cannot. Which component enforces this when mounting the secret?*

5.  **Discussion on Etcd Encryption:**
    *   Where are Kubernetes Secrets stored? (In `etcd`).
    *   By default, are they encrypted in `etcd`? (No, only base64 encoded).
    *   Why is enabling encryption at rest for `etcd` critical for protecting Secrets? (It protects the Secret data even if an attacker gains access to `etcd` backups or the raw `etcd` data files).
    *   **Security Note:** RBAC controls *API access* to Secrets. Etcd encryption protects Secrets *at rest*. Both are needed.

**🚀 Challenge Task 🚀**
*Imagine `mysecret` was not resource-named in the `secret-reader` Role (i.e., it allowed `get` on *all* secrets in the namespace). If an attacker compromised a Pod running as `sa-with-access`, how could they discover and exfiltrate all secrets in the `secret-access-lab` namespace using `kubectl` from within that pod? Provide the commands.*

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

**✨ Prediction Point ✨**
*If a Pod like `no-limits-pod` is deployed without CPU or memory limits, what are two potential negative impacts on the node it runs on and other Pods sharing that node?*
    *   **Discussion:**
        *   What could happen if many such Pods are deployed on a node without resource limits? (CPU/memory exhaustion on the node, affecting other Pods and Kubelet stability - a "noisy neighbor" DoS).
        *   How do `LimitRange` and `ResourceQuota` objects help mitigate this? (`LimitRange` sets default limits/requests for Pods in a namespace if not specified; `ResourceQuota` sets overall resource consumption limits for a namespace).
    *   **Security Note:** Always set resource requests and limits for your workloads.

**✅ Verification Point ✅**
*Explain the difference between `ResourceQuota` and `LimitRange`. Which one would you use to enforce that *every* Pod in a namespace must have memory limits specified, and which would you use to cap the total memory usage of *all* Pods in that namespace?*

2.  **Discuss API Server Overload (Conceptual):**
    *   **Scenario:** Imagine a script (or a compromised component) making thousands of API requests per second to the API Server.
    *   **Impact:** This could overwhelm the API Server, making it slow or unresponsive for legitimate users and control plane components.
    *   **Mitigation:**
        *   API Server has built-in rate limiting (though defaults might need tuning for very large clusters or specific abuse cases).
        *   Proper authentication and authorization to prevent unauthorized clients from making excessive requests.
        *   Monitoring API Server performance and request latencies.
    *   **Security Note:** Protecting the API Server from DoS is crucial for cluster availability.

**🚀 Challenge Task 🚀**
*Beyond API server rate limiting, what is one *proactive* measure a cluster administrator can implement at the network level or infrastructure level to add an additional layer of DoS protection for the Kubernetes API server, particularly against external threats?*

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

**✨ Prediction Point ✨**
*If an attacker gains the permission to create CronJobs in a namespace, how might this be more advantageous for persistence compared to just creating a regular Pod that they try to keep running?*
    *   **Discussion:**
        *   If an attacker has RBAC permissions to create CronJobs in a namespace, how could they use this for persistence? (They could schedule a CronJob to run a Pod with a malicious image or command periodically, e.g., to re-establish a reverse shell or exfiltrate data).
    *   **Mitigation:** Restrict permissions to create/manage CronJobs using RBAC. Monitor CronJob creation.

**✅ Verification Point ✅**
*Besides scheduling malicious commands, what other subtle persistence or information gathering tasks could an attacker schedule using a CronJob that might go unnoticed for longer? (Think about non-obvious actions).*

2.  **Discuss Backdoored Images in Deployments:**
    *   **Scenario:** An attacker manages to get a backdoored container image (e.g., containing a reverse shell binary) into a Deployment's Pod template.
    *   **Persistence:** Every time the Deployment scales up or a Pod is restarted, a new Pod with the backdoored image will be created, potentially re-establishing attacker access.
    *   **Mitigation:**
        *   Strong image security practices (scanning, trusted registries, image signing - covered in Supply Chain Security).
        *   RBAC to restrict who can modify Deployments.
        *   GitOps with manifest validation and review before applying changes.
    *   **Security Note:** Persistence through workload controllers like Deployments or DaemonSets is effective for attackers because Kubernetes actively tries to keep these workloads running.

**🚀 Challenge Task 🚀**
*An attacker has compromised a CI/CD pipeline that has permissions to apply Deployments to your cluster. Describe a change they could make to an existing Deployment manifest for a web application that would grant them persistent access to newly created Pods for that application, without obviously changing the main application container's image or command. (Hint: think about sidecars or init containers).*

**Cleanup Note:** Delete any namespaces or test resources created if not already done in individual exercises.

