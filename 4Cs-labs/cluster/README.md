# Cluster Security Lab Guide: Network Policies

## Learning Objectives

By the end of this lab, you will be able to:
- Understand Kubernetes network policy concepts and best practices
- Implement network segmentation using Kubernetes NetworkPolicy resources
- Configure ingress and egress rules for controlling pod-to-pod communication
- Apply namespace-based network isolation
- Test and validate network policy enforcement
- Mitigate common networking-related security risks in Kubernetes

## Overview of Cluster Security and Network Policies

Kubernetes network policies act as a firewall for controlling pod-to-pod communication. By default, all pods can communicate with any other pod in the cluster (an "allow all" policy). Network policies help implement the principle of least privilege for network communication.

Key network security concepts:

1. **Zero-Trust Networking**: Deny all traffic by default, only allowing explicitly permitted communication
2. **Network Segmentation**: Isolating workloads based on security requirements
3. **Ingress/Egress Control**: Controlling both incoming and outgoing traffic
4. **Namespace Isolation**: Restricting communication between different namespaces
5. **Micro-segmentation**: Fine-grained control of communication between specific pods
6. **Defense in Depth**: Combining multiple security measures for comprehensive protection

## Prerequisites

- A Kubernetes cluster with a CNI that supports NetworkPolicy (e.g., Calico, Cilium, Weave Net)
- kubectl configured to communicate with your cluster
- Basic understanding of Kubernetes networking concepts

```bash
# Verify your cluster and kubectl connection
kubectl version
kubectl get nodes
```

## Step-by-Step Instructions

### 1. Create Namespaces for Testing

We'll create two namespaces to demonstrate isolation between environments:

```bash
kubectl create namespace prod
kubectl create namespace dev
```

### 2. Deploy Test Applications

Deploy sample applications in both namespaces:

```bash
# Deploy in prod namespace
kubectl run nginx-prod --image=nginx --labels=app=nginx,env=prod -n prod --expose --port=80

# Deploy in dev namespace
kubectl run nginx-dev --image=nginx --labels=app=nginx,env=dev -n dev --expose --port=80
```

### 3. Test Default Connectivity (Before Network Policies)

```bash
# Create a test pod for connectivity checks
kubectl run test-pod --image=busybox --rm -it --restart=Never -- /bin/sh -c 'wget -qO- --timeout=2 http://nginx-prod.prod.svc.cluster.local && wget -qO- --timeout=2 http://nginx-dev.dev.svc.cluster.local'
```

By default, the pod should be able to access both services.

### 4. Examine the Network Policy Manifest

Review the `network-policy.yaml` file to understand the policies being implemented:

```bash
cat network-policy.yaml
```

### 5. Apply Network Policies

Apply the network policies to the cluster:

```bash
kubectl apply -f network-policy.yaml
```

### 6. Test Connectivity After Applying Network Policies

```bash
# Test from prod namespace
kubectl run test-prod --image=busybox --rm -it -n prod --restart=Never -- /bin/sh -c 'wget -qO- --timeout=2 http://nginx-prod.prod.svc.cluster.local && wget -qO- --timeout=2 http://nginx-dev.dev.svc.cluster.local'

# Test from dev namespace
kubectl run test-dev --image=busybox --rm -it -n dev --restart=Never -- /bin/sh -c 'wget -qO- --timeout=2 http://nginx-prod.prod.svc.cluster.local && wget -qO- --timeout=2 http://nginx-dev.dev.svc.cluster.local'
```

## Explanation of Network Policy Features

### Default Deny Policy

The first policy creates a default deny rule for all pods in the prod namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

This blocks all incoming and outgoing traffic for pods in the prod namespace unless explicitly allowed by other policies.

### Pod Isolation and Selective Ingress

The second policy allows specific ingress traffic to pods with the label `app: nginx` in the prod namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nginx-ingress
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          access: allowed
    ports:
    - protocol: TCP
      port: 80
```

This allows incoming traffic only from pods with the label `access: allowed` to the nginx pods, and only on port 80.

### Namespace-Based Rules

The third policy demonstrates namespace-based rules, allowing the dev namespace to access specific services in prod:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-dev-to-prod
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: dev
    ports:
    - protocol: TCP
      port: 80
```

## Additional Exercises

1. Create an egress policy that restricts outbound traffic from pods in the prod namespace
2. Implement a policy that allows traffic only from pods with specific service accounts
3. Configure a policy that permits traffic only on non-standard ports
4. Create a policy that combines namespace and pod selectors with logical AND

## Troubleshooting Network Policies

If your network policies aren't working as expected:

1. Confirm your CNI plugin supports NetworkPolicy
2. Check policy syntax and selectors
3. Verify labels on namespaces and pods
4. Use tools like `kubectl describe networkpolicy` to inspect policies
5. Consider temporary logging or tracing tools to debug network flows

## Conclusion

Network policies are a critical component of Kubernetes cluster security. By implementing proper network segmentation and isolation, you can prevent lateral movement by attackers and reduce the attack surface of your applications.

This lab has demonstrated how to create and apply various types of network policies to enforce the principle of least privilege for network communication within your Kubernetes cluster.

