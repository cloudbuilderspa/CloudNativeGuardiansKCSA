# Lab Guide: Software Supply Chain Security

This lab guide provides exercises focused on understanding and analyzing key aspects of software supply chain security in a Kubernetes context. The exercises are primarily conceptual and review-based, suitable for KCSA-level understanding, using examples rather than requiring complex tool installations.

**Note:** Ensure you have a text editor for reviewing manifest examples.

## Exercise 1: Analyzing Dockerfiles for Secure Practices

**Objective:** To identify secure and insecure practices in Dockerfile creation.

**Instructions:**

1.  **Review an Insecure Dockerfile Example:**
    *   Consider the following `Dockerfile.insecure`:
        ```dockerfile
        # Dockerfile.insecure
        FROM ubuntu:22.04 # Large base image
        LABEL maintainer="test@example.com"

        # Install multiple tools, some might not be needed in production
        RUN apt-get update && apt-get install -y \
            curl \
            git \
            python3 \
            python3-pip \
            vim \
            net-tools \
            && rm -rf /var/lib/apt/lists/*

        # Copy entire application directory (might include .git, temp files, etc.)
        COPY . /app
        WORKDIR /app

        # Install Python dependencies
        RUN pip3 install -r requirements.txt

        # Expose port and run application as root (default)
        EXPOSE 8080
        CMD ["python3", "app.py"]
        ```
    *   **Identify Potential Security Issues:**
        *   What is the risk of using a large base image like `ubuntu:22.04`?
        *   Why is installing tools like `git`, `vim`, `net-tools` potentially risky in a production image?
        *   What's the problem with `COPY . /app`?
        *   What's the risk of running the application as the root user (default)?

**✨ Prediction Point ✨**
*Before looking at the improved Dockerfile, if you were to make just *one* change to `Dockerfile.insecure` that would significantly reduce its attack surface from a software composition perspective, what would it be and why?*

2.  **Review an Improved Dockerfile Example (Multi-Stage):**
    *   Consider the following `Dockerfile.improved`:
        ```dockerfile
        # Dockerfile.improved

        # ---- Build Stage ----
        FROM python:3.9-slim as builder
        WORKDIR /app
        COPY requirements.txt .
        # Install only build dependencies, and do it efficiently
        RUN pip install --no-cache-dir --user -r requirements.txt

        COPY . .
        # (Imagine a build step here if it were a compiled language)

        # ---- Production Stage ----
        FROM python:3.9-alpine # Minimal base image
        WORKDIR /app

        # Create a non-root user and group
        RUN addgroup -S appgroup && adduser -S appuser -G appgroup

        # Copy only necessary artifacts from builder stage
        COPY --from=builder /app /app
        # Or, more specifically, if using --user flag in pip install:
        # COPY --from=builder /root/.local /home/appuser/.local

        # Ensure correct ownership if needed and switch to non-root user
        # RUN chown -R appuser:appgroup /app /home/appuser/.local (Adjust path if needed)
        USER appuser

        EXPOSE 8080
        CMD ["python3", "app.py"]
        ```
    *   **Identify Security Improvements:**
        *   How does using `python:3.9-alpine` as the final base improve security?
        *   What is the benefit of a multi-stage build in this context?
        *   How does creating and using a non-root user (`appuser`) enhance security?
        *   Why is `COPY --from=builder /app /app` (or more specific paths) better than `COPY . /app` in the production stage?

**✅ Verification Point ✅**
*In `Dockerfile.improved`, why is the step `RUN addgroup -S appgroup && adduser -S appuser -G appgroup` followed by `USER appuser` a more secure practice than simply running the application as root? What specific risks does this mitigate?*

3.  **Security Notes & KCSA Takeaways:**
    *   Always strive for minimal base images (Alpine, distroless).
    *   Use multi-stage builds to keep production images lean and free of build tools.
    *   Run applications as non-root users.
    *   Be explicit about files copied into the image; avoid copying unnecessary files (like `.git` directories, sensitive config files).

**🚀 Challenge Task 🚀**
*Consider the `Dockerfile.improved`. If the Python application `app.py` needed to write temporary log files to a `/logs` directory within the container, what additional Dockerfile instruction(s) would be needed to ensure the non-root `appuser` has permission to do so, without granting excessive permissions?*

## Exercise 2: Interpreting Image Vulnerability Scan Results (Conceptual)

**Objective:** To understand how to interpret output from an image vulnerability scanner.

**Instructions:**

1.  **Review Sample Vulnerability Scan Output:**
    *   Imagine you've scanned an older image, `nginx:1.18-alpine`, using a tool like Trivy. Here's a simplified, hypothetical output snippet:
        ```
        nginx:1.18-alpine (alpine 3.12.0)
        ==================================
        Total: 5 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 1, CRITICAL: 1)

        CRITICAL: CVE-2021-XXXX - libcrypto1.1 - Unspecified vulnerability
        Severity: CRITICAL
        Installed Version: 1.1.1g-r0
        Fixed Version: 1.1.1k-r0
        Description: ...

        HIGH: CVE-2020-YYYY - nginx - HTTP Request Smuggling
        Severity: HIGH
        Installed Version: 1.18.0
        Fixed Version: 1.19.0
        Description: ...

        MEDIUM: CVE-2019-ZZZZ - zlib - Out-of-bounds read
        Severity: MEDIUM
        Installed Version: 1.2.11-r1
        Fixed Version: 1.2.11-r3
        Description: ...
        ```

**✨ Prediction Point ✨**
*Given the scan results, if your organization has a policy to block deployments with any CRITICAL vulnerabilities, but allows HIGH vulnerabilities if a fix is not yet available in a stable base image, how would you proceed with the `nginx:1.18-alpine` image based on this output?*

2.  **Analysis and Discussion:**
    *   Identify the CRITICAL and HIGH severity vulnerabilities.
    *   For `CVE-2021-XXXX` in `libcrypto1.1`, what is the installed version and what is the fixed version?
    *   What actions should an organization take upon seeing this scan result?
        *   Update `libcrypto1.1` to `1.1.1k-r0` (likely by updating the base Alpine image version).
        *   Update `nginx` to `1.19.0` or later.
        *   Rebuild the application image with these updated components.
        *   Consider blocking deployment if critical vulnerabilities cannot be immediately remediated.
    *   Why is it important to scan not just direct dependencies but also OS packages in the base image?

**✅ Verification Point ✅**
*Explain the difference between a vulnerability in an OS package (like `libcrypto1.1`) versus a vulnerability in the application software itself (like `nginx`). Why might the remediation path differ for these two types of vulnerabilities found in the same image?*

3.  **Security Notes & KCSA Takeaways:**
    *   Image scanning is essential for identifying known vulnerabilities.
    *   Focus on remediating CRITICAL and HIGH severity vulnerabilities first.
    *   Scanning should be integrated into CI/CD pipelines and registries.
    *   Understand that "Fixed Version" indicates a patch is available.

**🚀 Challenge Task 🚀**
*Imagine a scenario where a vulnerability scanner reports a "MEDIUM" severity vulnerability in a library, but your development team assesses that your application does not use the specific vulnerable function within that library. What process or documentation would be essential to justify not immediately patching this vulnerability, and what are the ongoing responsibilities if you choose to accept this risk?*

## Exercise 3: Understanding Image Signing and Admission Control (Conceptual)

**Objective:** To understand the concept of image signing and how admission controllers can enforce policies based on signatures.

**Instructions (Conceptual Review):**

1.  **Image Signing Flow (Conceptual):**
    *   **CI/CD Pipeline:** After an image is built and tested, a tool like `Cosign` (from Sigstore) is used to sign the image.
    *   **Signature Storage:** The signature can be stored in the OCI registry alongside the image or in a transparency log like Rekor.
    *   **Key Management:** The private key used for signing must be securely managed. Keyless signing (using OIDC identities) is an option with Sigstore.

**✨ Prediction Point ✨**
*If an attacker manages to compromise the CI/CD pipeline's build server *after* an image is built but *before* it's signed, what kind of malicious action could they take regarding the image, and how would image signing (if properly implemented later in the step) help mitigate this?*

2.  **Admission Control for Signature Verification (Conceptual Example):**
    *   Review a simplified Kyverno policy manifest snippet (do not apply):
        ```yaml
        # kyverno-policy-example.yaml
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: check-image-signatures
        spec:
          validationFailureAction: Enforce # Block deployment if fails
          rules:
          - name: verify-image-signature
            match:
              resources:
                kinds:
                - Pod
            verifyImages:
            - image: "*" # Apply to all images
              key: | # Public key of the trusted signer
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                -----END PUBLIC KEY-----
              # Or use other attestations like keyless with specific issuer/subject
        ```
    *   **Discussion:**
        *   What is the role of this Kyverno `ClusterPolicy`? (To verify image signatures before allowing Pod deployment).
        *   What happens if an unsigned image or an image signed by an untrusted key is deployed? (Deployment is blocked due to `validationFailureAction: Enforce`).
        *   Where does the public key for verification come from? (It's configured in the policy and should correspond to the private key used for signing in CI/CD).
    *   **Security Note:** Image signing and admission control provide strong guarantees that only trusted and verified images run in your cluster.

**🚀 Challenge Task 🚀**
*Besides verifying signatures using a public key, tools like Kyverno can often verify images against other attestations (e.g., from Sigstore's keyless signing). If an image was signed "keylessly" using a CI/CD system's OIDC identity, what specific details would an admission controller policy need to check to ensure the image was signed by *your organization's* trusted CI/CD pipeline and not a malicious actor's pipeline?*

## Exercise 4: Reviewing a Software Bill of Materials (SBOM) Example

**Objective:** To understand the structure and utility of an SBOM.

**Instructions (Conceptual Review):**

1.  **Review a Snippet of an SBOM (CycloneDX JSON example):**
    ```json
    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version": 1,
      "metadata": {
        "timestamp": "2023-10-27T12:00:00Z",
        "tools": [ { "vendor": "Trivy", "name": "Trivy", "version": "0.45.0" } ],
        "component": {
          "type": "application",
          "name": "my-web-app",
          "version": "1.2.3"
        }
      },
      "components": [
        {
          "type": "library",
          "name": "requests",
          "version": "2.28.1",
          "purl": "pkg:pypi/requests@2.28.1"
        },
        {
          "type": "library",
          "name": "urllib3",
          "version": "1.26.12",
          "purl": "pkg:pypi/urllib3@1.26.12",
          "scope": "required" // This is a transitive dependency of 'requests'
        },
        {
          "type": "operating-system",
          "name": "alpine",
          "version": "3.18.0"
        }
      ]
    }
    ```

**✨ Prediction Point ✨**
*Looking at the SBOM, if `requests` version `2.28.1` was found to have a critical vulnerability, but `urllib3` version `1.26.12` was fine, would `my-web-app` still be considered affected? Why is understanding the full dependency tree important?*
2.  **Analysis and Discussion:**
    *   Identify a direct dependency of `my-web-app`. (e.g., `requests`)
    *   Identify a transitive dependency. (e.g., `urllib3` is a dependency of `requests`)
    *   If a new CVE is announced for `urllib3` version `1.26.12`, how would this SBOM help? (It allows you to quickly see that `my-web-app` is affected because it uses `requests` which in turn uses the vulnerable `urllib3`).
    *   What other information is present (tool used, timestamp, OS)?
    *   **Security Note:** SBOMs provide transparency into software components, aiding in vulnerability management, license compliance, and understanding supply chain risks.

**🚀 Challenge Task 🚀**
*SBOMs can be generated in various formats (SPDX, CycloneDX, etc.). Research and name one key advantage of using a standardized SBOM format compared to a proprietary or custom-text format for dependencies. How does this advantage contribute to better overall supply chain security management?*

## Exercise 5: Secure CI/CD Practices (Conceptual Discussion)

**Objective:** To discuss security best practices for CI/CD pipelines involved in building and deploying to Kubernetes.

**Instructions (Discussion Points):**

1.  **Scenario:** A CI/CD pipeline (e.g., GitHub Actions, Jenkins, GitLab CI) is responsible for:
    *   Checking out code from a Git repository.
    *   Building a container image.
    *   Pushing the image to a private container registry.
    *   Deploying the application (updating a Deployment) to a Kubernetes cluster.

**✨ Prediction Point ✨**
*Of the four responsibilities listed for the CI/CD pipeline, which step, if compromised, would likely grant an attacker the most direct and widespread ability to deploy malicious workloads into the Kubernetes cluster?*

2.  **Discussion Points:**
    *   **Registry Credentials:**
        *   How should the pipeline authenticate to the private container registry to push the image? (e.g., using short-lived tokens, service account credentials for the CI/CD system, platform's built-in secret management like GitHub Actions secrets).
        *   Why should these credentials *not* be hardcoded in the pipeline script?
    *   **Kubernetes Deployment Credentials:**
        *   If the pipeline deploys to Kubernetes, what kind of ServiceAccount should it use in the cluster? (A dedicated SA with least privilege, scoped to the target namespace, and only with permissions to update the specific Deployments/Services it manages).
        *   How can tools like `kubectl auth can-i --as=system:serviceaccount:<ns>:<sa>` help verify these minimal permissions?
    *   **Securing Code Before CI:**
        *   How do branch protection rules in Git (e.g., requiring reviews, passing status checks) contribute to supply chain security before code even reaches the CI pipeline? (Prevent direct pushes of potentially malicious or untested code to main branches).
    *   **Pipeline Integrity:** How would you protect the pipeline definition itself (e.g., `Jenkinsfile`, `.github/workflows/`) from unauthorized modifications? (Code reviews, branch protection on the SCM repository storing these files).
    *   **Security Note:** CI/CD pipelines are critical infrastructure and a prime target. Securing them with least privilege, secret management, and integrity checks is vital.

**🚀 Challenge Task 🚀**
*A CI/CD pipeline uses a long-lived static token to authenticate to Kubernetes. Describe a more secure alternative authentication method the pipeline could use, especially when running on a cloud provider or a Kubernetes cluster that supports workload identity federation. What are the benefits of this alternative?*

## Exercise 6: Analyzing an Artifact Repository Configuration (Conceptual)

**Objective:** To consider security configurations for an artifact (image) repository.

**Instructions (Discussion Points):**

1.  **Scenario:** An organization uses a private image repository (e.g., Harbor, Artifactory, AWS ECR, GCP Artifact Registry).

**✨ Prediction Point ✨**
*If an artifact repository does *not* support integrated vulnerability scanning, what is a key challenge organizations face in ensuring their stored images remain secure over time, even if they were scanned as "clean" during CI/CD?*

2.  **Discussion Points:**
    *   **Access Controls:**
        *   What types of users or systems would need to push images? (CI/CD systems, developers in specific cases).
        *   What types of users or systems would need to pull images? (Kubernetes nodes/Kubelets, developers, other CI/CD jobs).
        *   How can you implement least privilege for these actions? (e.g., specific user accounts or robot accounts with push/pull permissions scoped to particular repository paths or projects).
    *   **Vulnerability Scanning within the Repository:**
        *   Why is it beneficial for the repository itself to support or integrate with vulnerability scanners? (Can re-scan images periodically as new CVEs are found, can provide a central dashboard of vulnerabilities across all stored images).
    *   **Image Retention and Cleanup Policies:**
        *   What are the benefits of having policies to delete old, unused, or highly vulnerable images? (Reduces storage costs, reduces risk of deploying known-vulnerable software by mistake).

**✅ Verification Point ✅**
*Regarding access controls for an image repository, why is it important to differentiate between permissions to `push` images and permissions to `pull` images? Provide an example of a principal that might only need `pull` access and one that would need `push` access.*
    *   **Replication and Proxying:**
        *   If the repository replicates images to other regions/registries, how must this be secured? (Secure channels, integrity checks).
        *   If the repository acts as a pull-through cache for public registries (like Docker Hub), what policies should be in place? (e.g., only cache/proxy official images, scan proxied images).
    *   **Security Note:** A well-secured artifact repository is a key control point in the software supply chain.

**🚀 Challenge Task 🚀**
*Many organizations use immutable tags for their production container images (e.g., `myapp:1.2.3-prod` should never be overwritten). How can an image repository's features (or lack thereof) support or hinder the enforcement of immutable tags? What is a risk if tags are mutable in a production context?*

These conceptual exercises should help solidify your understanding of the different facets of software supply chain security relevant to KCSA.

