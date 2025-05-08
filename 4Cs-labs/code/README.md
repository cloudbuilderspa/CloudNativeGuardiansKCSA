# Code Security Lab Guide

## Learning Objectives

By the end of this lab, you will be able to:
- Understand code and software supply chain security principles
- Implement secure container build practices with multi-stage builds
- Configure minimal base images and non-root user security
- Implement vulnerability scanning in CI/CD pipelines
- Apply image signing and verification techniques
- Secure your application dependencies

## Overview of Code Security Concepts

Code security is the first C in the 4Cs model and involves securing your application code, dependencies, and build processes:

1. **Secure Coding Practices**: Writing code with security in mind
2. **Dependency Management**: Managing and securing third-party dependencies
3. **Container Image Security**: Building secure container images
4. **Supply Chain Security**: Securing the entire software supply chain
5. **Image Scanning**: Identifying and remediating vulnerabilities
6. **Image Signing**: Verifying image authenticity and integrity

## Lab Environment Setup

Ensure you have the following tools installed:

```bash
# Check Docker installation
docker --version

# Check for vulnerability scanning tools
trivy --version || echo "Trivy not installed"

# Install Trivy if needed
# For macOS: brew install aquasecurity/trivy/trivy
# For Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## Step-by-Step Instructions

### 1. Examine the Secure Dockerfile

Review the `secure-build.yaml` manifest to understand the security practices implemented:

```bash
cat secure-build.yaml
```

### 2. Build a Secure Container Image

Create a simple application and a Dockerfile implementing security best practices:

```bash
# Create a simple application
mkdir -p app
cat > app/app.py << EOF
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, Secure World!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

# Create a secure Dockerfile
cat > Dockerfile << EOF
# Build stage
FROM python:3.9-slim AS builder

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.9-slim

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY app/ .

# Use non-root user
USER appuser

# Configure security options
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run with minimal capabilities
EXPOSE 8080
CMD ["python", "app.py"]
EOF

# Build the image
docker build -t secure-app:latest .
```

### 3. Scan the Image for Vulnerabilities

Use Trivy to scan your container image for vulnerabilities:

```bash
# Scan the image with Trivy
trivy image secure-app:latest
```

### 4. Implement Image Signing

Set up image signing with cosign:

```bash
# Install cosign (if not already installed)
# For macOS: brew install cosign
# For Linux: go install github.com/sigstore/cosign/cmd/cosign@latest

# Generate a keypair
cosign generate-key-pair

# Sign the image
cosign sign --key cosign.key secure-app:latest

# Verify the signature
cosign verify --key cosign.pub secure-app:latest
```

## Explanation of Security Features

### Multi-Stage Builds

Multi-stage builds help create smaller, more secure images:

- **Stage 1**: Build environment with all development dependencies
- **Stage 2**: Runtime environment with only necessary packages
- Benefits: Smaller attack surface, reduced vulnerabilities

### Minimal Base Images

Using minimal base images improves security:

- Alpine or distroless images have fewer packages and less attack surface
- Reduces the number of potential vulnerabilities
- Leads to faster scanning and deployment

### Non-Root User Configuration

Running containers as non-root prevents privilege escalation:

- Create a dedicated user in the Dockerfile
- Switch to that user using the `USER` directive
- Never run containers with unnecessary privileges

### Package Vulnerability Scanning

Regular scanning helps identify and remediate vulnerabilities:

- Scan both application dependencies and base images
- Include scanning in CI/CD pipelines
- Establish policies for handling identified vulnerabilities

### Image Signing and Verification

Signing ensures image authenticity and integrity:

- Sign images after building
- Verify signatures before deployment
- Integrate with admission controllers to enforce signature verification

## Additional Exercises

1. Create a policy that rejects deployments of container images with HIGH or CRITICAL vulnerabilities
2. Implement Software Bill of Materials (SBOM) generation for your container images
3. Configure your Kubernetes admission controller to verify image signatures using cosign
4. Build a pipeline that automatically updates dependencies when security patches are available

## Testing and Validation

### Test Container as Non-Root User

Verify that the container runs as a non-root user:

```bash
docker run -it --rm secure-app:latest id
```

### Verify Image Size Reduction

Compare the size of a multi-stage build with a single-stage build:

```bash
# Check the size of your optimized image
docker images secure-app:latest
```

## Conclusion

Code security is the foundation of the 4Cs security model. By implementing secure coding practices, proper dependency management, secure container builds, vulnerability scanning, and image signing, you create a strong first line of defense for your cloud-native applications.

These practices help prevent vulnerabilities from entering your environment and provide assurance about the integrity and authenticity of your software supply chain.

In the next lab, you'll explore Container Security to build upon this foundation.

