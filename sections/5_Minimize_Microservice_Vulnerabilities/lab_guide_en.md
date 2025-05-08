# Lab Guide: Minimizing Microservice Vulnerabilities

This lab guide offers practical exercises and conceptual reviews to help you understand how to minimize vulnerabilities in microservices running on Kubernetes. These activities are tailored for a KCSA-level understanding and assume `kubectl` access to a Kubernetes cluster.

**Note:** Create a test namespace for these exercises if needed: `kubectl create namespace microservice-lab`. Remember to clean up resources afterward.

## Exercise 1: Container Image Security Inspection

**Objective:** To understand key aspects of container image security.

**Instructions:**

1.  **Conceptual Vulnerability Scan:**
    *   **Discussion:** Tools like Trivy, Clair, and Grype are used to scan container images for known vulnerabilities (CVEs) in OS packages and application dependencies.
    *   **Activity (If a tool like Trivy is installed locally):**
        ```bash
        # Example: trivy image nginx:latest
        ```
        If you don't have a scanner, search online for "Trivy nginx scan results" to see what typical output looks like.
    *   **Observe:** Notice the types of vulnerabilities found, their severity, and the affected packages/libraries.
    *   **Security Note:** Regularly scanning images in your CI/CD pipeline and in your registry (Image Repository Security) is crucial for identifying and mitigating known vulnerabilities before deployment.

2.  **Analyzing Dockerfiles for Best Practices (Examples):**
    *   **Minimal Base Images - Review the following conceptual Dockerfile snippets:**
        *   **Less Secure (Larger Base):**
            ```dockerfile
            # Dockerfile.less-secure
            FROM ubuntu:latest
            RUN apt-get update && apt-get install -y some-tool python3 app-dependencies
            COPY . /app
            WORKDIR /app
            CMD ["python3", "my_microservice.py"]
            ```
        *   **More Secure (Minimal Base - Alpine):**
            ```dockerfile
            # Dockerfile.more-secure-alpine
            FROM alpine:latest
            RUN apk add --no-cache python3 py3-pip && pip3 install --no-cache-dir -r requirements.txt
            COPY . /app
            WORKDIR /app
            CMD ["python3", "my_microservice.py"]
            ```
        *   **Discussion:** Compare the potential attack surface. The `ubuntu:latest` image contains many more utilities and libraries than `alpine:latest`, increasing the chance of vulnerabilities. "Distroless" images would be even more minimal.
    *   **Multi-Stage Builds - Review this Dockerfile example:**
        ```dockerfile
        # Dockerfile.multistage
        # Build Stage
        FROM golang:1.19 as builder
        WORKDIR /app
        COPY . .
        RUN CGO_ENABLED=0 GOOS=linux go build -o my_microservice .

        # Production Stage
        FROM alpine:latest
        # FROM gcr.io/distroless/static-debian11 # Alternative distroless base
        WORKDIR /app
        COPY --from=builder /app/my_microservice .
        # COPY --from=builder /app/templates ./templates # If app needs static assets
        # COPY --from=builder /app/static ./static
        USER 1001:1001 # Run as non-root
        CMD ["./my_microservice"]
        ```
        *   **Discussion:** How does this multi-stage build reduce the final image size and attack surface? (The final image only contains the compiled binary and minimal OS, not the Go SDK or build tools).
    *   **Security Note:** Using minimal base images and multi-stage builds are fundamental image hardening techniques.

3.  **Checking Image Registry (Conceptual):**
    *   **Discussion:**
        *   Why is it important to use trusted private registries for your organization's images? (Control over content, access control, integration with scanners).
        *   What are the risks of pulling images directly from public registries like Docker Hub without verification? (Images could be malicious, contain critical vulnerabilities, or be unofficial).
        *   What does "image signing" (e.g., Notary, Sigstore) provide? (Assurance of image integrity and provenance).
    *   **Security Note:** Your image repository is a critical part of your secure supply chain.

## Exercise 2: Secure Inter-Service Communication (Network Policies)

**Objective:** To use Network Policies to restrict communication between microservice Pods.

**Instructions:**

1.  **Create a Namespace:**
    ```bash
    kubectl create namespace interservice-sec-lab
    ```

2.  **Deploy two Microservice Pods (e.g., `frontend` and `backend`):**
    *   `frontend-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: frontend-svc
          namespace: interservice-sec-lab
          labels:
            app: myapp
            tier: frontend
        spec:
          containers:
          - name: nginx
            image: nginx # Simulates frontend
            ports:
            - containerPort: 80
        ```
    *   `backend-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: backend-svc
          namespace: interservice-sec-lab
          labels:
            app: myapp
            tier: backend
        spec:
          containers:
          - name: nginx # Simulates backend
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   Apply both:
        ```bash
        kubectl apply -f frontend-pod.yaml -n interservice-sec-lab
        kubectl apply -f backend-pod.yaml -n interservice-sec-lab
        ```
    *   Wait for Pods: `kubectl get pods -n interservice-sec-lab -w`
    *   Get `backend-svc` IP: `BACKEND_IP=$(kubectl get pod backend-svc -n interservice-sec-lab -o jsonpath='{.status.podIP}')`

3.  **Verify Initial Communication (Frontend to Backend):**
    ```bash
    kubectl exec -it frontend-svc -n interservice-sec-lab -- curl --connect-timeout 2 -I $BACKEND_IP
    ```
    *   **Expected Outcome:** Should succeed (HTTP 200 OK).

4.  **Apply a Network Policy to `backend-svc` to only allow ingress from `frontend-svc`:**
    *   `backend-netpol.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: backend-ingress-policy
          namespace: interservice-sec-lab
        spec:
          podSelector:
            matchLabels:
              tier: backend # Applies to backend-svc
          policyTypes:
          - Ingress
          ingress:
          - from:
            - podSelector:
                matchLabels:
                  tier: frontend # Allow from frontend-svc
            ports:
            - protocol: TCP
              port: 80
        ```
    *   Apply: `kubectl apply -f backend-netpol.yaml -n interservice-sec-lab`

5.  **Verify Communication (Frontend to Backend - should still work):**
    ```bash
    kubectl exec -it frontend-svc -n interservice-sec-lab -- curl --connect-timeout 2 -I $BACKEND_IP
    ```
    *   **Expected Outcome:** Should succeed.

6.  **Attempt Communication from another Pod (if you deploy one without `tier: frontend` label) or from a different namespace to `backend-svc` (Conceptual):**
    *   **Discussion:** If another Pod (e.g., `kubectl run test-curl --image=curlimages/curl -n interservice-sec-lab --rm -it -- /bin/sh` then `curl $BACKEND_IP`) tries to access `backend-svc`, it should be blocked by the Network Policy.
    *   **Security Note:** Network Policies are a crucial first step for microservice network segmentation.

7.  **Clean up:**
    ```bash
    kubectl delete namespace interservice-sec-lab
    # rm frontend-pod.yaml backend-pod.yaml backend-netpol.yaml (if you saved them)
    ```

## Exercise 3: Service Mesh Concepts (Conceptual/Analysis)

**Objective:** To understand how a Service Mesh can enhance microservice security.

**Instructions (No actual deployment - conceptual analysis):**

1.  **Review a Sample Istio `PeerAuthentication` manifest (for mTLS):**
    ```yaml
    # Sample Istio PeerAuthentication for mTLS
    apiVersion: security.istio.io/v1beta1
    kind: PeerAuthentication
    metadata:
      name: default-mtls
      namespace: your-microservice-ns # Target namespace
    spec:
      mtls:
        mode: STRICT # Enforces mTLS
    ```
    *   **Discussion:**
        *   What does `mode: STRICT` imply for services in `your-microservice-ns`? (All communication must be mTLS; unencrypted traffic is rejected).
        *   How does this enhance security over just Network Policies? (Provides identity verification and encryption for L7 traffic, not just L3/L4 connectivity).

2.  **Review a Sample Istio `AuthorizationPolicy` manifest (for L7 AuthZ):**
    ```yaml
    # Sample Istio AuthorizationPolicy
    apiVersion: security.istio.io/v1beta1
    kind: AuthorizationPolicy
    metadata:
      name: backend-reader-policy
      namespace: your-microservice-ns
    spec:
      selector:
        matchLabels:
          app: backend-service # Policy applies to backend-service
      action: ALLOW
      rules:
      - from:
        - source:
            principals: ["cluster.local/ns/your-microservice-ns/sa/frontend-sa"] # Allow from frontend's SA
        to:
        - operation:
            methods: ["GET"]
            paths: ["/api/data/*"]
    ```
    *   **Discussion:**
        *   What does this policy allow? (Allows `frontend-sa` to make `GET` requests to paths under `/api/data/` on `backend-service`).
        *   How is this different from RBAC? (RBAC controls access to Kubernetes API resources; Service Mesh AuthZ policies control access between workloads/services at the application layer).
    *   **Security Note:** Service Meshes provide powerful tools for zero-trust networking between microservices. Understanding their capabilities is important for KCSA.

## Exercise 4: API Security for Endpoints (Conceptual)

**Objective:** To discuss security considerations for microservice API endpoints.

**Instructions (Conceptual Discussion):**

1.  **Scenario:** A microservice `OrderService` exposes an endpoint `POST /orders`.
2.  **Discussion Points:**
    *   **Authentication:** How would you ensure only authenticated clients can call this endpoint?
        *   **API Gateway:** The gateway could validate a JWT or API key before forwarding the request.
        *   **`OrderService` itself:** If no gateway, or for internal calls, `OrderService` might need to validate a JWT passed in an `Authorization` header.
    *   **Authorization:** Once authenticated, how would `OrderService` decide if the caller is *allowed* to create an order? (e.g., check scopes in a JWT, call an external authorization service, internal logic based on user ID).
    *   **Input Validation:** What kind of input validation should `OrderService` perform on the request body for `POST /orders`? (Check for required fields, data types, lengths, malicious characters to prevent XSS, injection, etc.).
    *   **Rate Limiting:** Why might rate limiting be important for this endpoint? (Prevent abuse, DoS).
    *   **Security Note:** Each microservice endpoint is a potential attack vector and must be secured with appropriate authN, authZ, and input validation.

## Exercise 5: Secure Secrets Consumption by Microservices

**Objective:** To practice securely mounting and accessing Secrets in a microservice Pod.

**Instructions:**

1.  **Create a Namespace and a Secret:**
    ```bash
    kubectl create namespace app-secrets-lab
    kubectl create secret generic app-api-key --from-literal=api-key='abcdef1234567890' -n app-secrets-lab
    ```

2.  **Deploy a Pod (simulating a microservice) that mounts this Secret as a volume:**
    *   `microservice-pod-secret.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: my-microservice
          namespace: app-secrets-lab
        spec:
          automountServiceAccountToken: false # Good practice if not needed
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", "echo 'My API key is:'; cat /etc/app-secrets/api-key; echo; sleep 3600"]
            volumeMounts:
            - name: api-key-volume
              mountPath: "/etc/app-secrets"
              readOnly: true
          volumes:
          - name: api-key-volume
            secret:
              secretName: app-api-key
        ```
    *   Apply: `kubectl apply -f microservice-pod-secret.yaml -n app-secrets-lab`

3.  **Verify Access and Discuss:**
    *   Check logs: `kubectl logs my-microservice -n app-secrets-lab`
    *   **Expected Outcome:** The logs should show the API key read from the file.
    *   **Discussion:**
        *   Why is mounting as a read-only file generally safer than as an environment variable? (Less prone to accidental logging, not inherited by child processes as easily).
        *   What RBAC permissions would the ServiceAccount used by this Pod (default SA, in this case) need related to this Secret for the Pod to start? (The Kubelet, acting with the Pod's SA privileges, needs to be able to `get` the Secret `app-api-key` from the API server to mount it).
    *   **Security Note:** Ensure RBAC tightly controls which ServiceAccounts can access specific Secrets.

4.  **Clean up:**
    ```bash
    kubectl delete namespace app-secrets-lab
    # rm microservice-pod-secret.yaml (if saved)
    ```

## Exercise 6: Observability for Security (Logging Focus)

**Objective:** To understand the role of logging in microservice security.

**Instructions:**

1.  **Deploy a Simple Pod that Logs to Stdout:**
    *   `logging-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: logging-app
          namespace: default # Or your test namespace
        spec:
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", "i=0; while true; do echo \"Log entry $i: User 'testUser' attempted action X at $(date)\"; i=$((i+1)); sleep 5; done"]
        ```
    *   Apply: `kubectl apply -f logging-pod.yaml`

2.  **View Logs:**
    ```bash
    kubectl logs -f logging-app
    ```
    (Ctrl+C to stop)

3.  **Discussion:**
    *   **What security-relevant information *should* a microservice log?**
        *   Authentication attempts (success/failure, source IP, username if applicable).
        *   Authorization decisions (granted/denied, for what resource/action).
        *   Significant operations or state changes initiated by users/systems.
        *   Critical errors or exceptions that might indicate compromise or malfunction.
        *   API request details (endpoint, source, user-agent, but be careful with PII).
    *   **What sensitive information should *never* be logged by a microservice?**
        *   Raw passwords, API keys, session tokens, full credit card numbers.
        *   Detailed PII unless absolutely necessary and properly protected/masked.
        *   Encryption keys.
    *   **How would centralized logging (e.g., ELK stack, Splunk, cloud provider solutions) help in correlating security events from multiple microservices?** (Provides a single place to search, analyze, and alert on logs from all services, making it easier to trace an attack цепочка or identify widespread issues).
    *   **Security Note:** Proper logging is essential for detection, response, and forensics. However, logs themselves can become a target if they contain sensitive data or are not adequately protected.

4.  **Clean up:**
    ```bash
    kubectl delete pod logging-app
    # rm logging-pod.yaml (if saved)
    # kubectl delete namespace microservice-lab (if you created it and are done)
    ```

This lab guide provides a starting point. Experiment further with these concepts in your cluster.

