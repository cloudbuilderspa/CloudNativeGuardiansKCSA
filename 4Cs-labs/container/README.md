# Container Security Lab Guide

## Learning Objectives

By the end of this lab, you will be able to:
- Understand key container security concepts and best practices
- Implement security contexts for pods and containers
- Configure resource limits to prevent resource exhaustion attacks
- Apply seccomp profiles to restrict system calls
- Use non-root users and read-only file systems to enhance security
- Validate configurations against Pod Security Standards

## Overview of Container Security Concepts

Container security involves multiple layers of protection:

1. **Container Image Security**: Scanning for vulnerabilities, using minimal base images
2. **Runtime Security**: Configuring appropriate permissions and restrictions
3. **Resource Management**: Setting CPU and memory limits to prevent DoS attacks
4. **Access Control**: Running containers as non-root users with least privilege
5. **Isolation**: Implementing proper namespace and cgroup isolation
6. **System Call Filtering**: Restricting available system calls with seccomp profiles

## Lab Environment Setup

Ensure you have access to a Kubernetes cluster and kubectl is configured properly:

```bash
kubectl version
kubectl get nodes
```

## Step-by-Step Instructions

### 1. Examine the Secure Pod Manifest

Review the `secure-pod.yaml` file to understand the security features implemented:

```bash
cat secure-pod.yaml
```

### 2. Apply the Secure Pod to the Cluster

```bash
kubectl apply -f secure-pod.yaml
```

### 3. Verify the Pod is Running

```bash
kubectl get pods
kubectl describe pod secure-nginx
```

## Explanation of Security Features

### Security Context

The pod and container security contexts define permissions and capabilities:

- **runAsNonRoot: true**: Prevents the container from running as the root user
- **runAsUser: 1000**: Specifies which non-root user ID to use
- **readOnlyRootFilesystem: true**: Makes the root filesystem read-only
- **allowPrivilegeEscalation: false**: Prevents privilege escalation
- **capabilities**: Drops all capabilities by default, adds only what's necessary

### Resource Limits

Resource limits prevent resource exhaustion attacks:

- **requests**: Guaranteed resources for the container
- **limits**: Maximum resources the container can use

### Seccomp Profile

Seccomp (secure computing mode) restricts the system calls that a container can make to the Linux kernel:

- The profile is set to the runtime default, which provides a good balance of security and functionality

## Testing and Validation

### Test Security Context Restrictions

Try to create a file inside the container:

```bash
kubectl exec -it secure-nginx -- touch /test.txt
```

This should fail due to the read-only filesystem.

### Verify Process Running as Non-Root

```bash
kubectl exec -it secure-nginx -- id
```

You should see that the process is running as user 1000, not root.

### Test Resource Limits

```bash
kubectl exec -it secure-nginx -- /bin/sh -c "stress --cpu 2"
```

Observe that the container cannot exceed its CPU limit.

## Additional Exercises

1. Modify the secure-pod.yaml to add an AppArmor profile
2. Create a Pod Security Policy that enforces these security requirements
3. Use Trivy or another scanning tool to check the nginx container image for vulnerabilities

## Conclusion

Container security involves multiple layers of defense. By implementing security contexts, resource limits, non-root users, and read-only filesystems, you can significantly reduce the attack surface of your containerized applications.

This lab demonstrated best practices that align with the Pod Security Standards (PSS) and industry recommendations for securing containers in a Kubernetes environment.

