# Lab Guide: Kubernetes Security Fundamentals for Cluster Hardening

This lab guide provides hands-on exercises to reinforce your understanding of Kubernetes security fundamentals crucial for cluster hardening. These exercises align with KCSA-level knowledge and assume `kubectl` access to a Kubernetes cluster.

**Note:** Ensure you have a namespace for testing (e.g., `test-hardening-ns`) or create one: `kubectl create namespace test-hardening-ns`. Remember to clean up resources after completing the labs.

## Exercise 1: Pod Security Admission (PSA) Configuration

**Objective:** To understand and configure Pod Security Admission for a namespace.

**Instructions:**

1.  **Create a Test Namespace:**
    ```bash
    kubectl create namespace psa-lab
    ```

2.  **Label the Namespace for `baseline` PSS level (enforce, audit, warn):**
    *   This configuration will enforce the `baseline` policy, audit any violations against the `baseline` policy (writing to audit logs), and warn the user if a Pod spec violates the `baseline` policy. We set it to the latest version available.
    ```bash
    kubectl label --overwrite ns psa-lab \
      pod-security.kubernetes.io/enforce=baseline \
      pod-security.kubernetes.io/enforce-version=latest \
      pod-security.kubernetes.io/audit=baseline \
      pod-security.kubernetes.io/audit-version=latest \
      pod-security.kubernetes.io/warn=baseline \
      pod-security.kubernetes.io/warn-version=latest
    ```
    *   Verify labels: `kubectl get ns psa-lab --show-labels`

3.  **Attempt to Deploy a Pod that Violates the `baseline` Policy (Privileged Pod):**
    *   Create `privileged-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: privileged-pod
          namespace: psa-lab
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
            securityContext:
              privileged: true # This violates baseline
        ```
    *   Attempt to apply: `kubectl apply -f privileged-pod.yaml`
    *   **Expected Outcome:** The Pod creation should be **denied** due to the `enforce=baseline` label. You should see an error message indicating the violation. If you check audit logs (conceptual for this lab), an audit event would be generated. A warning would also be displayed to the user.
    *   **Security Note:** This demonstrates PSA preventing the deployment of overly privileged Pods.

4.  **Attempt to Deploy a Pod that Violates `baseline` (e.g., HostPath volume):**
    *   Create `hostpath-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: hostpath-pod
          namespace: psa-lab
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
            volumeMounts:
            - name: host-var
              mountPath: /mnt/var
          volumes:
          - name: host-var
            hostPath:
              path: /var # Mounting sensitive host directories like /var is generally disallowed by baseline
              type: Directory
        ```
    *   Attempt to apply: `kubectl apply -f hostpath-pod.yaml`
    *   **Expected Outcome:** Pod creation should be **denied**. `hostPath` volumes for sensitive host directories are typically restricted by the `baseline` policy.

5.  **Deploy a Compliant Pod:**
    *   Create `compliant-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: compliant-pod
          namespace: psa-lab
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
            securityContext:
              runAsNonRoot: true
              runAsUser: 1001
              allowPrivilegeEscalation: false
              capabilities:
                drop: ["ALL"]
              seccompProfile:
                type: RuntimeDefault
        ```
    *   Apply: `kubectl apply -f compliant-pod.yaml`
    *   **Expected Outcome:** The Pod should be created successfully as it adheres to `baseline` (and likely `restricted`) PSS.
    *   Check status: `kubectl get pod -n psa-lab compliant-pod`

6.  **Clean up:**
    ```bash
    kubectl delete namespace psa-lab
    rm privileged-pod.yaml hostpath-pod.yaml compliant-pod.yaml
    ```

## Exercise 2: RBAC Configuration

**Objective:** To practice creating and applying RBAC roles for a ServiceAccount.

**Instructions:**

1.  **Create a Namespace for this exercise:**
    ```bash
    kubectl create namespace rbac-lab
    ```

2.  **Create a new ServiceAccount:**
    ```bash
    kubectl create serviceaccount my-app-sa -n rbac-lab
    ```

3.  **Create a Role that grants read-only access to Pods in the `rbac-lab` namespace:**
    *   Create `pod-reader-role.yaml`:
        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: rbac-lab
          name: pod-reader
        rules:
        - apiGroups: [""] # Core API group
          resources: ["pods", "pods/log"]
          verbs: ["get", "list", "watch"]
        ```
    *   Apply: `kubectl apply -f pod-reader-role.yaml`

4.  **Create a RoleBinding to bind the `my-app-sa` ServiceAccount to the `pod-reader` Role:**
    ```bash
    kubectl create rolebinding my-app-sa-pod-reader-binding \
      --role=pod-reader \
      --serviceaccount=rbac-lab:my-app-sa \
      -n rbac-lab
    ```
    *   Verify: `kubectl describe rolebinding my-app-sa-pod-reader-binding -n rbac-lab`

5.  **Deploy a Pod using this ServiceAccount and verify its permissions:**
    *   Create `test-rbac-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: test-rbac-pod
          namespace: rbac-lab
        spec:
          serviceAccountName: my-app-sa
          containers:
          - name: kubectl-container
            image: bitnami/kubectl:latest # Image with kubectl
            command: ["sleep", "3600"]
        ```
    *   Apply: `kubectl apply -f test-rbac-pod.yaml`
    *   Wait for the Pod to be running: `kubectl get pod test-rbac-pod -n rbac-lab -w`
    *   Exec into the Pod: `kubectl exec -it test-rbac-pod -n rbac-lab -- sh`
    *   Inside the Pod, attempt to list Pods (should succeed):
        ```sh
        kubectl get pods -n rbac-lab
        ```
    *   Attempt to list Secrets (should fail):
        ```sh
        kubectl get secrets -n rbac-lab
        ```
    *   Exit the pod: `exit`
    *   **Expected Outcome:** The Pod, using `my-app-sa`, can list Pods in `rbac-lab` but cannot list Secrets, demonstrating the applied RBAC permissions.
    *   **Security Note:** This exercise demonstrates the principle of least privilege for ServiceAccounts.

6.  **Clean up:**
    ```bash
    kubectl delete namespace rbac-lab
    rm pod-reader-role.yaml test-rbac-pod.yaml
    ```

## Exercise 3: Secrets Management

**Objective:** To practice creating and using Kubernetes Secrets in Pods.

**Instructions:**

1.  **Create a Namespace for this exercise:**
    ```bash
    kubectl create namespace secrets-lab
    ```

2.  **Create a generic Secret (e.g., with a username/password):**
    ```bash
    kubectl create secret generic my-db-credentials \
      --from-literal=username='dbuser' \
      --from-literal=password='S3cr3tP@sswOrd' \
      -n secrets-lab
    ```
    *   Inspect the Secret (notice it's base64 encoded): `kubectl get secret my-db-credentials -n secrets-lab -o yaml`

3.  **Mount the Secret as files into a Pod:**
    *   Create `secret-file-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: secret-file-pod
          namespace: secrets-lab
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "echo 'Secrets mounted. Username:'; cat /etc/db-credentials/username; echo 'Password:'; cat /etc/db-credentials/password; sleep 3600"]
            volumeMounts:
            - name: db-creds-volume
              mountPath: "/etc/db-credentials"
              readOnly: true
          volumes:
          - name: db-creds-volume
            secret:
              secretName: my-db-credentials
        ```
    *   Apply: `kubectl apply -f secret-file-pod.yaml`
    *   Check logs: `kubectl logs secret-file-pod -n secrets-lab`
    *   **Expected Outcome:** The logs should show the decoded username and password, read from the mounted files.
    *   **Security Note:** Mounting as read-only files is generally preferred over environment variables.

4.  **Mount parts of the Secret as environment variables:**
    *   Create `secret-env-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: secret-env-pod
          namespace: secrets-lab
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "echo 'Username from env: $DB_USER'; echo 'Password from env: $DB_PASS'; sleep 3600"]
            env:
            - name: DB_USER
              valueFrom:
                secretKeyRef:
                  name: my-db-credentials
                  key: username
            - name: DB_PASS
              valueFrom:
                secretKeyRef:
                  name: my-db-credentials
                  key: password
        ```
    *   Apply: `kubectl apply -f secret-env-pod.yaml`
    *   Check logs: `kubectl logs secret-env-pod -n secrets-lab`
    *   **Expected Outcome:** Logs should show username and password from environment variables.
    *   **Discussion:** Compare the security implications of file mounts vs. environment variables (env vars can be exposed more easily via logs, child processes, or `describe pod`).

5.  **Clean up:**
    ```bash
    kubectl delete namespace secrets-lab
    rm secret-file-pod.yaml secret-env-pod.yaml
    ```

## Exercise 4: Network Policy Implementation

**Objective:** To implement basic network segmentation using Network Policies. (Requires a CNI plugin that supports Network Policies, e.g., Calico, Cilium, Weave).

**Instructions:**

1.  **Create a Namespace for this exercise:**
    ```bash
    kubectl create namespace netpol-lab
    ```

2.  **Deploy two simple web server Pods (e.g., Nginx) with distinct labels:**
    *   `pod-a.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: pod-a
          namespace: netpol-lab
          labels:
            app: myapp
            role: frontend
        spec:
          containers:
          - name: nginx
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   `pod-b.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: pod-b
          namespace: netpol-lab
          labels:
            app: myapp
            role: backend
        spec:
          containers:
          - name: nginx
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   Apply both: `kubectl apply -f pod-a.yaml -f pod-b.yaml`
    *   Wait for them to be running. Get their IP addresses: `kubectl get pods -n netpol-lab -o wide`

3.  **Verify Pods can communicate initially:**
    *   Exec into `pod-a` and try to `curl` `pod-b`'s IP:
        ```bash
        POD_B_IP=$(kubectl get pod pod-b -n netpol-lab -o jsonpath='{.status.podIP}')
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Expected Outcome:** Communication should succeed (HTTP 200 OK).

4.  **Create a `default-deny` Ingress Network Policy for the `netpol-lab` namespace:**
    *   `default-deny-ingress.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-ingress
          namespace: netpol-lab
        spec:
          podSelector: {} # Selects all pods
          policyTypes:
          - Ingress
        ```
    *   Apply: `kubectl apply -f default-deny-ingress.yaml`

5.  **Verify Pods can NO LONGER communicate (for ingress to pod-b):**
    *   Repeat the `curl` from `pod-a` to `pod-b`:
        ```bash
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Expected Outcome:** Communication should now fail (timeout or connection refused) because no ingress is explicitly allowed to `pod-b`.

6.  **Create a Network Policy to allow ingress to `pod-b` (role: backend) from `pod-a` (role: frontend) on port 80:**
    *   `allow-frontend-to-backend.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: allow-frontend-to-backend
          namespace: netpol-lab
        spec:
          podSelector:
            matchLabels:
              app: myapp
              role: backend # Policy applies to pod-b
          policyTypes:
          - Ingress
          ingress:
          - from:
            - podSelector:
                matchLabels:
                  app: myapp
                  role: frontend # Allow from pod-a
            ports:
            - protocol: TCP
              port: 80
        ```
    *   Apply: `kubectl apply -f allow-frontend-to-backend.yaml`

7.  **Verify `pod-a` can now communicate with `pod-b`, but other ingress is still denied:**
    *   Repeat the `curl` from `pod-a` to `pod-b`:
        ```bash
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Expected Outcome:** Communication should succeed again.
    *   **Security Note:** Network Policies are essential for micro-segmentation and implementing a zero-trust model.

8.  **Clean up:**
    ```bash
    kubectl delete namespace netpol-lab
    rm pod-a.yaml pod-b.yaml default-deny-ingress.yaml allow-frontend-to-backend.yaml
    ```

## Exercise 5: Audit Logging Inspection (Conceptual/If Possible)

**Objective:** To understand how to check for audit log configuration and what to look for.

**Instructions:**

1.  **Discuss API Server Audit Log Flags (Conceptual):**
    *   If you have access to inspect the API Server manifest (e.g., `minikube ssh` then `sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml`), look for flags like:
        *   `--audit-log-path`: Specifies the file path for audit logs.
        *   `--audit-policy-file`: Specifies the path to the audit policy file defining what to log.
        *   `--audit-log-maxage`, `--audit-log-maxbackup`, `--audit-log-maxsize`: Flags for log rotation.
    *   **Discussion:** Why are these flags important? What information does an audit policy file control (levels, stages)? Refer to the `main_concepts.md` for details on audit policy.

2.  **Attempt to Find an Audit Event (If logs are accessible and you know the path):**
    *   This step is highly dependent on your cluster setup. If using Minikube and you found an `--audit-log-path` like `/var/log/kubernetes/audit.log`:
        ```bash
        minikube ssh
        sudo tail -f /var/log/kubernetes/audit.log # Or the path you found
        ```
    *   In another terminal, perform a `kubectl` action (e.g., `kubectl get pods -n kube-system`).
    *   Try to identify the corresponding log entry. Look for your username/client, the verb (`get`), and the resource (`pods`).
    *   **Expected Outcome (Conceptual):** Gain an appreciation for the detail and volume of audit logs. Understand that manual inspection is hard, highlighting the need for automated analysis tools.
    *   **Security Note:** Audit logs are your primary source for detecting and investigating security incidents. Ensure they are enabled, properly configured, and securely stored.

**Cleanup Note:** Remember to delete any namespaces or other resources created specifically for these labs if they are not automatically cleaned up by deleting the namespace.

