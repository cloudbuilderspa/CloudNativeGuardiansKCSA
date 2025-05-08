# Lab Guide: Monitoring, Logging, and Runtime Security

This lab guide provides exercises to help you understand key aspects of monitoring, logging, and runtime security in Kubernetes. The focus is on conceptual understanding and using `kubectl` for inspection and basic interaction, suitable for KCSA-level knowledge.

**Note:** Create a test namespace for these exercises if needed: `kubectl create namespace runtime-lab`. Remember to clean up resources afterward.

## Exercise 1: Kubernetes Audit Log Inspection (Conceptual & Basic Interaction)

**Objective:** Understand what Kubernetes audit logs capture and their importance for security.

**Instructions:**

1.  **Task 1 (Conceptual): Review Audit Policy Snippet & API Server Flags**
    *   Consider this snippet from a Kubernetes audit policy file:
        ```yaml
        # audit-policy-sample.yaml
        apiVersion: audit.k8s.io/v1
        kind: Policy
        rules:
        # Log exec commands in pods at RequestResponse level
        - level: RequestResponse
          resources:
          - group: "" # core
            resources: ["pods/exec"]
        # Log Secret creations, deletions, and updates
        - level: RequestResponse
          resources:
          - group: "" # core
            resources: ["secrets"]
          verbs: ["create", "delete", "update", "patch"]
        # Log RBAC changes
        - level: RequestResponse
          groups: ["rbac.authorization.k8s.io"]
        # Log other requests at Metadata level
        - level: Metadata
        ```
    *   **Discussion:**
        *   What API server flags are used to enable auditing and specify the policy file? (Typically `--audit-log-path=/var/log/kubernetes/audit.log` and `--audit-policy-file=/etc/kubernetes/audit-policy.yaml`).
        *   In the sample policy, why are `pods/exec` and `secrets` modifications logged at `RequestResponse` level? (To capture full details of potentially high-risk operations).
        *   Why are other requests logged at `Metadata`? (To reduce log volume while still capturing essential event information).

2.  **Task 2 (If Possible): Finding an Event in Audit Logs**
    *   **Note:** Accessing raw audit logs depends heavily on your Kubernetes setup (Minikube, Kind, managed cloud service). For Minikube, you might `minikube ssh` and find logs typically in `/var/log/kubernetes/audit.log` or similar, if enabled.
    *   If accessible:
        1.  Perform a simple `kubectl` action, e.g., `kubectl get pods -n kube-system`.
        2.  Try to `tail` or `grep` the audit log for this event. Look for entries containing your username (from `kubectl config view`), the verb `get`, and the resource `pods`.
        ```bash
        # Inside Minikube VM or wherever audit logs are:
        # sudo grep '"verb":"get"' /var/log/kubernetes/audit.log | grep '"resource":"pods"' | tail -n 5
        ```
    *   **Observe (even conceptually):**
        *   `user.username`: Who made the request.
        *   `verb`: The action (e.g., `get`, `create`, `delete`).
        *   `objectRef.resource`: The type of resource (e.g., `pods`, `secrets`).
        *   `objectRef.namespace`: The namespace.
        *   `responseStatus.code`: The HTTP status code of the response.
    *   **Discussion:** Why are audit logs crucial for security monitoring, incident investigation, and compliance?

3.  **Security Notes & KCSA Takeaways:**
    *   Audit logs are a primary source for detecting unauthorized API activity.
    *   A well-defined audit policy is essential to capture meaningful events without excessive noise.
    *   Logs should be securely stored and regularly reviewed or analyzed by automated systems.

## Exercise 2: Application Log Analysis for Security Events

**Objective:** To recognize security-relevant information in application logs and understand logging best practices.

**Instructions:**

1.  **Deploy a Sample Logging Application Pod:**
    *   Create `logging-app-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: sample-logging-app
          namespace: runtime-lab # Use your test namespace
        spec:
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", 
                      "echo \"INFO: $(date) Service started successfully.\"; \
                       sleep 5; \
                       echo \"INFO: $(date) User 'alice' logged in from IP 10.1.2.3\"; \
                       sleep 5; \
                       echo \"WARN: $(date) User 'bob' failed login attempt (invalid password) from IP 192.168.1.100\"; \
                       sleep 5; \
                       echo \"INFO: $(date) Data record ID '789' accessed by user 'alice'\"; \
                       sleep 5; \
                       echo \"ERROR: $(date) Payment processing failed for transaction 'xyz123': Insufficient funds\"; \
                       sleep 600"]
        ```
    *   Apply: `kubectl apply -f logging-app-pod.yaml -n runtime-lab`

2.  **View Application Logs:**
    ```bash
    kubectl logs sample-logging-app -n runtime-lab
    # Use -f for live tailing: kubectl logs -f sample-logging-app -n runtime-lab
    ```

3.  **Analysis and Discussion:**
    *   Which log entries are security-relevant? (e.g., "User 'alice' logged in", "User 'bob' failed login attempt").
    *   What actions might a security analyst take based on multiple "failed login attempt" logs for user 'bob' from various IPs? (Investigate potential brute-force attack, temporarily lock account, alert user).
    *   How would structured logging (e.g., JSON format: `{"timestamp": "...", "level": "INFO", "user": "alice", "action": "login", "source_ip": "10.1.2.3"}`) make these logs easier for a SIEM or automated tool to parse and analyze compared to plain text?
    *   What sensitive information should *not* be present in these logs (e.g., actual passwords, full session tokens)?

4.  **Clean up:**
    ```bash
    kubectl delete pod sample-logging-app -n runtime-lab
    # rm logging-app-pod.yaml (if saved)
    ```

## Exercise 3: Basic Resource Monitoring for Anomalies

**Objective:** To use `kubectl top` to observe resource usage and discuss its security implications.

**Instructions:**

1.  **Deploy a Pod Designed to Consume CPU (if not already in your test namespace):**
    *   Create `cpu-hog-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: cpu-hog
          namespace: runtime-lab
        spec:
          containers:
          - name: hog
            image: busybox
            command: ["sh", "-c", "while true; do true; done"] # Basic busy loop
            resources:
              requests:
                cpu: "10m" # Small request to ensure it gets scheduled
              limits:
                cpu: "100m" # Limit to avoid overwhelming small test clusters
        ```
    *   Apply: `kubectl apply -f cpu-hog-pod.yaml -n runtime-lab`
    *   Wait for it to run: `kubectl get pod cpu-hog -n runtime-lab -w`

2.  **Observe Resource Usage:**
    *   Get the name of the node where `cpu-hog` is running:
        ```bash
        NODE_NAME=$(kubectl get pod cpu-hog -n runtime-lab -o jsonpath='{.spec.nodeName}')
        echo "Pod cpu-hog is running on node: $NODE_NAME"
        ```
    *   Monitor Pod CPU usage:
        ```bash
        kubectl top pod cpu-hog -n runtime-lab
        ```
    *   Monitor Node CPU and Memory usage:
        ```bash
        kubectl top node $NODE_NAME
        ```
    *   (Run these `top` commands a few times to see the usage).

3.  **Discussion:**
    *   How could consistently high or unexpectedly spiking resource usage for a Pod indicate a security issue? (e.g., cryptojacking malware consuming CPU, a DoS attack causing high network/CPU, a runaway process due to exploitation).
    *   How do resource `limits` (CPU, memory) defined in a Pod spec help mitigate the impact of such issues on the node and other Pods? (They constrain the misbehaving Pod, preventing it from starving other workloads).
    *   What other metrics (beyond CPU/memory) might be useful for security monitoring? (Network I/O, disk I/O, number of running processes).

4.  **Clean up:**
    ```bash
    kubectl delete pod cpu-hog -n runtime-lab
    # rm cpu-hog-pod.yaml (if saved)
    ```

## Exercise 4: Simulating Basic Incident Response: Isolating a Pod

**Objective:** To understand how Network Policies can be used for basic incident containment.

**Instructions:**

1.  **Setup: Deploy Two Pods in `runtime-lab` Namespace:**
    *   `app-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: my-app-pod
          namespace: runtime-lab
          labels:
            app: my-app # Important label for policy
        spec:
          containers:
          - name: nginx
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   `attacker-sim-pod.yaml`: (This simulates another Pod trying to connect)
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: attacker-sim
          namespace: runtime-lab
        spec:
          containers:
          - name: curler
            image: curlimages/curl
            command: ["sleep", "3600"] # Keep it running for exec
        ```
    *   Apply both:
        ```bash
        kubectl apply -f app-pod.yaml -n runtime-lab
        kubectl apply -f attacker-sim-pod.yaml -n runtime-lab
        ```
    *   Wait for Pods: `kubectl get pods -n runtime-lab -w`
    *   Get `my-app-pod` IP: `APP_POD_IP=$(kubectl get pod my-app-pod -n runtime-lab -o jsonpath='{.status.podIP}')`

2.  **Verify Initial Connectivity:**
    ```bash
    kubectl exec -it attacker-sim -n runtime-lab -- curl --connect-timeout 2 -I $APP_POD_IP
    ```
    *   **Expected Outcome:** Connection should succeed (Nginx HTTP response).

3.  **Scenario: `my-app-pod` is Suspected of Compromise. Isolate It.**
    *   Create `isolate-my-app-pod.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: isolate-my-app-pod-policy
          namespace: runtime-lab
        spec:
          podSelector:
            matchLabels:
              app: my-app # Selects my-app-pod
          policyTypes:
          - Ingress
          - Egress
          # No ingress or egress rules defined means all traffic is denied
        ```
    *   Apply the isolation policy: `kubectl apply -f isolate-my-app-pod.yaml -n runtime-lab`

4.  **Verify Isolation:**
    *   Attempt connection from `attacker-sim` to `my-app-pod` again:
        ```bash
        kubectl exec -it attacker-sim -n runtime-lab -- curl --connect-timeout 2 -I $APP_POD_IP
        ```
        **Expected Outcome:** Connection should now **fail** (timeout).
    *   Attempt outbound connection from `my-app-pod` (e.g., to an external site, or even `kubernetes.default.svc`):
        ```bash
        kubectl exec -it my-app-pod -n runtime-lab -- curl --connect-timeout 2 -I https://www.google.com
        ```
        **Expected Outcome:** Connection should **fail** (timeout).

5.  **Discussion:**
    *   How does this Network Policy help contain a potential incident involving `my-app-pod`? (Prevents lateral movement from the Pod and exfiltration/C2 communication to outside).
    *   What other `kubectl` commands would be part of an initial response to investigate the "compromised" `my-app-pod` once isolated? (`kubectl logs my-app-pod`, `kubectl describe pod my-app-pod`, potentially `kubectl exec` if deemed safe and necessary for live forensics).
    *   What does `kubectl cordon <node-name>` do, and why might it be used in this scenario?

6.  **Clean up:**
    ```bash
    kubectl delete namespace runtime-lab
    # rm app-pod.yaml attacker-sim-pod.yaml isolate-my-app-pod.yaml (if saved)
    ```

## Exercise 5: Understanding Runtime Security Tooling (Conceptual - Falco)

**Objective:** To understand the types of threats a runtime security tool like Falco can detect.

**Instructions (Conceptual Review):**

1.  **Review Sample Falco Rules:**
    *   **Rule 1: Shell spawned in a container**
        ```yaml
        - rule: Terminal shell in container
          desc: A shell was spawned in a container with an attached terminal.
          condition: evt.type = execve and evt.dir = < and proc.tty != 0 and container.id != host and proc.name in (bash, sh, zsh, ksh, fish, dash, tcsh, csh)
          output: "Shell spawned in a container (user=%user.name container_id=%container.id container_name=%container.name image=%container.image.repository proc_name=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty)"
          priority: WARNING
        ```
    *   **Rule 2: Write below sensitive root directory**
        ```yaml
        - rule: Write below root dir
          desc: An attempt to write to a file below /root
          condition: evt.type = open and evt.dir = < and fd.name startswith /root and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)
          output: "File created/modified below /root by (user=%user.name command=%proc.cmdline file=%fd.name)"
          priority: ERROR
        ```
    *   **Rule 3: Unexpected outbound network connection**
        ```yaml
        - rule: Unexpected outbound connection
          desc: An outbound network connection was made from a container to an unexpected destination or port.
          condition: syscall.type = connect and evt.dir = > and fd.typechar = 4 and fd.sip != private_ipv4_ चाँडै and not trusted_connection
          # 'trusted_connection' would be a macro defining allowed connections
          output: "Unexpected outbound connection (container=%container.name image=%container.image.repository connection=%fd.name)"
          priority: NOTICE
        ```

2.  **Discussion:**
    *   For each rule:
        *   What kind of malicious or suspicious activity is it trying to detect?
        *   Why is detecting this activity important for runtime security?
    *   How does Falco (conceptually) get the information to evaluate these rules? (Primarily by observing system calls (syscalls) made by processes, either via a kernel module or eBPF. It can also ingest Kubernetes audit logs).
    *   What actions might an organization take when Falco generates an alert for one of these rules? (Investigate, isolate, remediate).

3.  **Security Notes & KCSA Takeaways:**
    *   Runtime security tools provide visibility into the actual behavior of workloads.
    *   Rule-based detection is effective for known malicious patterns.
    *   Understanding what these tools monitor (syscalls, network, file access) is key to appreciating their value.

This lab guide should give you a better practical and conceptual understanding of monitoring, logging, and runtime security in Kubernetes. Remember to always apply these concepts within the context of your organization's specific security requirements and risk tolerance.

