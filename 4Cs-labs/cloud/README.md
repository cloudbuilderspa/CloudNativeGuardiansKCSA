# Cloud Security Lab Guide

This lab guide provides practical exercises and conceptual reviews to help you understand how to implement and manage cloud security in Kubernetes environments. It focuses on security concerns at the Cloud layer of the 4Cs (Cloud, Cluster, Container, Code) security model. These activities are tailored for a KCSA-level understanding and assume `kubectl` access to a Kubernetes cluster.

**Note:** Create a test namespace for these exercises if needed: `kubectl create namespace cloud-security-lab`. Remember to clean up resources afterward.

## Exercise 1: Storage Encryption and Security

**Objective:** To understand and implement encrypted storage for Kubernetes workloads.

**Instructions:**

1. **Encrypted StorageClass Implementation:**
   * **Discussion:** Cloud providers offer various ways to encrypt storage at rest. We'll explore how to set up and use an encrypted StorageClass in Kubernetes.
   * Create an encrypted StorageClass manifest:
     ```yaml
     # encrypted-storageclass.yaml
     apiVersion: storage.k8s.io/v1
     kind: StorageClass
     metadata:
       name: encrypted-storage
     provisioner: kubernetes.io/gce-pd  # For GKE, use appropriate provisioner for your cloud
     parameters:
       type: pd-standard
       encrypted: "true"  # Enable encryption
       # diskEncryptionKmsKey: projects/PROJECT_ID/locations/LOCATION/keyRings/RING_NAME/cryptoKeys/KEY_NAME  # Optional: Specify customer-managed key
     reclaimPolicy: Delete
     allowVolumeExpansion: true
     volumeBindingMode: WaitForFirstConsumer
     ```
   * Apply the StorageClass:
     ```bash
     kubectl apply -f encrypted-storageclass.yaml
     ```
   * **Security Note:** Encryption at rest protects data when physical disks are accessed, decommissioned, or stolen. It's a regulatory requirement for many compliance standards.

**✨ Prediction Point ✨**
*If your organization decides to transition from cloud provider-managed encryption keys to customer-managed keys (CMEK) for your encrypted storage volumes, what operational and security considerations would you need to address? Specifically, what happens to existing PVs during this transition?*

2. **Create a PersistentVolumeClaim using the encrypted StorageClass:**
   * Create a PVC manifest:
     ```yaml
     # encrypted-pvc.yaml
     apiVersion: v1
     kind: PersistentVolumeClaim
     metadata:
       name: secure-data-pvc
       namespace: cloud-security-lab
     spec:
       accessModes:
         - ReadWriteOnce
       storageClassName: encrypted-storage
       resources:
         requests:
           storage: 10Gi
     ```
   * Apply the PVC:
     ```bash
     kubectl apply -f encrypted-pvc.yaml -n cloud-security-lab
     ```
   * Verify the PVC:
     ```bash
     kubectl get pvc secure-data-pvc -n cloud-security-lab
     ```

**✅ Verification Point ✅**
*Examine the output of `kubectl describe pvc secure-data-pvc -n cloud-security-lab`. What fields indicate that this PVC is using the encrypted storage class? If a volume has been provisioned, how would you verify in your cloud provider console that encryption is actually enabled for this volume?*

3. **Deploy a Pod that uses the encrypted PVC:**
   * Create a Pod manifest:
     ```yaml
     # secure-pod.yaml
     apiVersion: v1
     kind: Pod
     metadata:
       name: secure-data-pod
       namespace: cloud-security-lab
     spec:
       containers:
         - name: app
           image: nginx
           volumeMounts:
             - name: secure-data
               mountPath: "/secure-data"
           resources:
             requests:
               memory: "64Mi"
               cpu: "250m"
             limits:
               memory: "128Mi"
               cpu: "500m"
       volumes:
         - name: secure-data
           persistentVolumeClaim:
             claimName: secure-data-pvc
     ```
   * Apply the Pod:
     ```bash
     kubectl apply -f secure-pod.yaml -n cloud-security-lab
     ```
   * Verify the Pod:
     ```bash
     kubectl get pod secure-data-pod -n cloud-security-lab
     ```
   * Test writing data to the encrypted volume:
     ```bash
     kubectl exec -it secure-data-pod -n cloud-security-lab -- bash -c "echo 'This data is stored on an encrypted volume' > /secure-data/test.txt && cat /secure-data/test.txt"
     ```

**🚀 Challenge Task 🚀**
*Create a policy using your cloud provider's tools (or conceptualize if not available) that enforces all storage volumes must be encrypted. How would you implement auditing to detect non-compliant volumes? Consider using tools like OPA/Gatekeeper, cloud provider policy frameworks, or other compliance tools.*

4. **Clean up:**
   ```bash
   kubectl delete pod secure-data-pod -n cloud-security-lab
   kubectl delete pvc secure-data-pvc -n cloud-security-lab
   kubectl delete storageclass encrypted-storage
   ```

## Exercise 2: Network Security in Cloud Environments

**Objective:** To understand and implement network security controls for Kubernetes in cloud environments.

**Instructions:**

1. **Cloud Provider Network Controls (Conceptual):**
   * **Discussion:**
     * What are the primary network security boundaries in a cloud-hosted Kubernetes cluster?
       - VPC/VNet and subnets
       - Security Groups / Firewall Rules
       - Network Policies inside the cluster
       - Service Mesh controls (if used)
     * How do cloud provider network security controls (like Security Groups, NACLs) differ from Kubernetes Network Policies?
     * Why would you need both cloud-level and Kubernetes-level network controls?

**✨ Prediction Point ✨**
*If you secure your Kubernetes API server with cloud provider firewall rules to only allow access from specific IP ranges, but don't configure any authentication or authorization, what security risks remain? Why would this be considered an incomplete security posture?*

2. **Implementing a Cloud-Level Network Security Zone (Conceptual):**
   * **Discussion:** 
     * How would you design network segmentation for a Kubernetes cluster using cloud provider tools?
     * What are the key considerations for placing control plane components, worker nodes, and related services like databases?
   
   * **Network Architecture Diagram (Conceptual):**
     ```
     [Internet] --> [Cloud Load Balancer] --> [Ingress Controller (in Public Subnet)]
                                                      ↓
     [Management VPN] --> [Bastion Host] --> [Kubernetes Control Plane (in Private Subnet)]
                                                      ↓
                                         [Worker Nodes (in Private Subnet)]
                                                      ↓
                                      [Database Services (in Isolated Subnet)]
     ```

**✅ Verification Point ✅**
*For the network architecture described above, explain how you would configure cloud provider firewall rules (Security Groups in AWS, Firewall Rules in GCP, Network Security Groups in Azure) to secure traffic flow between the Ingress Controller in the public subnet and the Worker Nodes in the private subnet. What specific ports and protocols would you allow?*

3. **Private Kubernetes API Configuration (Conceptual):**
   * **Discussion:**
     * Why is it safer to keep your Kubernetes API server private (not exposed to the internet)?
     * What are the implications for CI/CD pipelines, developer access, and monitoring tools?
     * How can you securely access a private API server when needed (e.g., VPN, bastion hosts, cloud provider private access)?

**🚀 Challenge Task 🚀**
*Design a network security architecture for a multi-environment Kubernetes deployment (dev, staging, prod) across multiple cloud availability zones. Include considerations for disaster recovery, cross-zone communication, secured API access, and zero-trust principles. Create a simple diagram or bulleted description of your security zones and controls.*

## Exercise 3: Identity and Access Management for Cloud Resources

**Objective:** To understand and configure secure identity and access patterns for cloud resources used by Kubernetes.

**Instructions:**

1. **Cloud IAM Roles for Kubernetes (Conceptual):**
   * **Discussion:**
     * What IAM roles/permissions does Kubernetes need at the cloud provider level?
     * Why is the principle of least privilege especially important for cloud permissions?
     * How do node IAM roles/identities differ from pod/workload identities?

**✨ Prediction Point ✨**
*If all worker nodes in your Kubernetes cluster use the same overly permissive IAM role (with S3/Blob Storage admin permissions, database admin permissions, etc.), what would the security impact be if a single pod in your cluster is compromised? How could an attacker potentially pivot from this position?*

2. **Configuring Pod Identity for Cloud Resource Access:**
   * **Discussion:** Different cloud providers have mechanisms to grant pods access to cloud resources:
     * GCP: Workload Identity
     * AWS: IAM Roles for Service Accounts (IRSA)
     * Azure: Pod Identity / Workload Identity
   
   * **Example Setup for AWS IRSA (conceptual):**
     1. Create an IAM OIDC provider for your cluster
     2. Create an IAM role with appropriate permissions and trust policy
     3. Create a Kubernetes ServiceAccount associated with the IAM role:
        ```yaml
        # s3-reader-serviceaccount.yaml
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: s3-reader
          namespace: cloud-security-lab
          annotations:
            eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/s3-reader-role
        ```
     4. Use this ServiceAccount in your Pod:
        ```yaml
        # s3-reader-pod.yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: s3-reader-pod
          namespace: cloud-security-lab
        spec:
          serviceAccountName: s3-reader
          containers:
          - name: app
            image: amazon/aws-cli
            command: ['sleep', '3600']
          # Additional Pod configuration...
        ```

**✅ Verification Point ✅**
*After configuring pod identity (like AWS IRSA, GCP Workload Identity, or Azure Pod Identity), how would you verify that a pod is correctly assuming the intended cloud identity? What commands or tools would you use to confirm it can access only the authorized resources?*

3. **Secret Management with Cloud Provider Tools (Conceptual):**
   * **Discussion:**
     * How do cloud-native secret management services (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) compare to Kubernetes Secrets?
     * What are the benefits of external secret management?
     * What patterns can be used to securely inject secrets from cloud providers into pods?

**🚀 Challenge Task 🚀**
*Design a secure access pattern for a microservice that needs to access both a cloud-managed database and object storage. Using cloud IAM and pod identity mechanisms, how would you implement least-privilege access for the service? Include considerations for secret rotation, access monitoring, and breach containment.*

## Exercise 4: Cloud Security Best Practices

**Objective:** To review and implement cloud security best practices for Kubernetes environments.

**Instructions:**

1. **Infrastructure as Code Security (Conceptual):**
   * **Discussion:**
     * Why is IaC security scanning important for cloud-hosted Kubernetes?
     * What types of security issues can be caught early in IaC templates?
     * How do tools like Checkov, tfsec, or cloud provider security scanners help?
   
   * **Example of a secure Terraform snippet for a Kubernetes cluster node group:**
     ```hcl
     # Example of secure Terraform for EKS node group
     resource "aws_eks_node_group" "secure_nodes" {
       cluster_name    = aws_eks_cluster.main.name
       node_group_name = "secure-node-group"
       node_role_arn   = aws_iam_role.node_role.arn
       subnet_ids      = aws_subnet.private[*].id  # Use private subnets only
       
       scaling_config {
         desired_size = 3
         max_size     = 5
         min_size     = 1
       }
       
       # Enable detailed monitoring
       instance_types = ["m5.large"]
       
       # Use launch template for additional security configurations
       launch_template {
         id      = aws_launch_template.secure_node.id
         version = aws_launch_template.secure_node.latest_version
       }
       
       # Proper tags for cost allocation and security tracking
       tags = {
         Environment = "production"
         ManagedBy   = "terraform"
         SecurityPatchStatus = "up-to-date"
       }
     }
     ```

**✨ Prediction Point ✨**
*In the Terraform example above, what security benefits do you gain by placing nodes in private subnets rather than public subnets? What additional configuration would be needed to allow these nodes to download container images and system updates?*

2. **Cloud-Native Security Controls (Conceptual):**
   * **Discussion:**
     * How can you leverage cloud provider security services to enhance Kubernetes security?
     * What types of monitoring and detection capabilities should you enable?
     * How do these integrate with Kubernetes security controls?
   
   * **Security controls to consider:**
     * Cloud Infrastructure Entitlements Management (CIEM)
     * Cloud Security Posture Management (CSPM)
     * Cloud Workload Protection Platforms (CWPP)
     * Cloud Provider native security services (Guard Duty, Security Command Center, Defender for Cloud)

**✅ Verification Point ✅**
*Explain how a CSPM tool would help detect and remediate a misconfigured Kubernetes cluster running in a cloud environment. Give three specific misconfigurations a CSPM might identify that could pose security risks to your Kubernetes workloads.*

3. **Data Protection in Cloud Environments:**
   * **Discussion:**
     * Beyond storage encryption, what other data protection mechanisms are important?
     * How would you implement data classification and protection for different sensitivity levels?
     * What considerations should be made for data backup and disaster recovery?

**🚀 Challenge Task 🚀**
*Create a cloud security checklist for Kubernetes deployments in your organization. Include at least three critical checks in each of the following areas: Identity and Access Management, Network Security, Data Protection, Cluster Configuration, and Monitoring/Logging. For each check, identify the risk it mitigates and how to implement it.*

## Exercise 5: Monitoring and Compliance for Cloud Security

**Objective:** To implement effective monitoring and ensure compliance of cloud resources used by Kubernetes.

**Instructions:**

1. **Cloud Resource Monitoring (Conceptual):**
   * **Discussion:**
     * What cloud resources associated with Kubernetes should be monitored for security?
     * How do cloud audit logs complement Kubernetes audit logs?
     * What events and metrics indicate potential security issues?

**✨ Prediction Point ✨**
*If you notice unusual API calls from a worker node's instance profile (like attempts to access unrelated cloud resources), what could this indicate and what immediate investigation steps would you take?*

2. **Implementing Compliance as Code:**
   * **Example OPA Gatekeeper constraint template for enforcing encrypted PVCs:**
     ```yaml
     # require-encrypted-storage.yaml
     apiVersion: templates.gatekeeper.sh/v1beta1
     kind: ConstraintTemplate
     metadata:
       name: requireencryptedstorage
       annotations:
         description: "Requires all PVCs to use encrypted storage classes."
     spec:
       crd:
         spec:
           names:
             kind: RequireEncryptedStorage
           validation:
             openAPIV3Schema:
               type: object
               properties:
                 encryptedStorageClasses:
                   type: array
                   items:
                     type: string
       targets:
         - target: admission.k8s.gatekeeper.sh
           rego: |
             package requireencryptedstorage
             
             violation[{"msg": msg}] {
               input.review.kind.kind == "PersistentVolumeClaim"
               sc := input.review.object.spec.storageClassName
               not sc_is_encrypted(sc)
               msg := sprintf("PVC '%v' uses non-encrypted storage class '%v'", [input.review.object.metadata.name, sc])
             }
             
             sc_is_encrypted(sc) {
               encrypted_sc := input.parameters.encryptedStorageClasses[_]
               sc == encrypted_sc
             }
     ```

## Exercise 6: Pod Security Standards and Configurations

**Objective:** To understand and implement Kubernetes Pod Security Standards and secure pod configurations.

**Instructions:**

1. **Understanding Pod Security Standards (PSS):**
   * **Discussion:**
     * What are the three Pod Security Standards profiles (Privileged, Baseline, Restricted) and their use cases?
     * How does Pod Security Standards differ from Pod Security Policies (deprecated)?
     * What security threats do PSS configurations mitigate?

   * **The PSS Enforcement Levels:**
     * **Privileged:** Unrestricted policy, providing the widest possible level of permissions
     * **Baseline:** Minimally restrictive policy which prevents known privilege escalations
     * **Restricted:** Heavily restricted policy, following security best practices

**✨ Prediction Point ✨**
*If a pod requires access to host namespaces or privileged capabilities to function, which Pod Security Standard level would it need? What security implications would this have, and what compensating controls might you implement?*

2. **Exploring the Pod Security Manifest:**
   * Review the pod-security.yaml manifest to understand the security configurations:
     ```bash
     kubectl apply -f pod-security.yaml --dry-run=client -o yaml
     ```
   * **Key components in the manifest:**
     * Namespace configurations with PSS enforcement labels
     * Pod security context configurations
     * Container security settings
     * Resource limits and requests
     * Service Account with restricted permissions

**✅ Verification Point ✅**
*Examine the security contexts in the pod-security.yaml file. Identify three security controls that are implemented and explain what threats each one mitigates. Which PSS profile (Privileged, Baseline, or Restricted) do these settings align with?*

3. **Implementing Pod Security Standards:**
   * Apply the pod-security.yaml manifest to create namespaces with PSS enforcement:
     ```bash
     kubectl apply -f pod-security.yaml
     ```
   * Verify the namespace labels that enforce Pod Security Standards:
     ```bash
     kubectl get ns pss-restricted --show-labels
     kubectl get ns pss-baseline --show-labels
     ```
   * Observe the Pod Security admission controller messages:
     ```bash
     kubectl describe ns pss-restricted
     kubectl describe ns pss-baseline
     ```

4. **Testing Pod Security Enforcement:**
   * Try to deploy a privileged pod in the restricted namespace:
     ```yaml
     # privileged-pod.yaml
     apiVersion: v1
     kind: Pod
     metadata:
       name: privileged-pod
       namespace: pss-restricted
     spec:
       containers:
       - name: privileged-container
         image: nginx
         securityContext:
           privileged: true
     ```
   * Apply the pod and observe the result:
     ```bash
     kubectl apply -f privileged-pod.yaml
     ```
   * Try to deploy a pod with a more secure configuration:
     ```yaml
     # secure-pod.yaml
     apiVersion: v1
     kind: Pod
     metadata:
       name: secure-pod
       namespace: pss-restricted
     spec:
       securityContext:
         runAsNonRoot: true
         seccompProfile:
           type: RuntimeDefault
       containers:
       - name: secure-container
         image: nginx
         securityContext:
           allowPrivilegeEscalation: false
           capabilities:
             drop: ["ALL"]
           readOnlyRootFilesystem: true
         resources:
           limits:
             cpu: "500m"
             memory: "512Mi"
           requests:
             cpu: "100m"
             memory: "128Mi"
     ```

**🚀 Challenge Task 🚀**
*Create a custom Pod Security Standard enforcement strategy for a multi-tenant Kubernetes cluster. Define which controls should be enforced at the namespace level vs. the admission controller level. Consider how you would handle exceptions for system workloads that require elevated privileges while maintaining strong security for tenant workloads.*

5. **Security Context Deep Dive:**
   * **Pod-level Security Context:**
     * Explore different Pod-level security settings:
       ```yaml
       securityContext:
         runAsUser: 1000
         runAsGroup: 3000
         fsGroup: 2000
         runAsNonRoot: true
         seccompProfile:
           type: RuntimeDefault
       ```
     * What is the difference between `runAsUser` and `runAsNonRoot`?
     * Why is the RuntimeDefault seccomp profile recommended?

   * **Container-level Security Context:**
     * Explore container-specific security settings:
       ```yaml
       securityContext:
         allowPrivilegeEscalation: false
         privileged: false
         readOnlyRootFilesystem: true
         capabilities:
           drop: ["ALL"]
           add: ["NET_BIND_SERVICE"]
       ```
     * Why is it important to drop ALL capabilities and only add what's needed?
     * What does `readOnlyRootFilesystem: true` protect against?

**✅ Verification Point ✅**
*Consider a scenario where a malicious container attempts a container escape to access the host system. Identify three security context settings that would help prevent this attack and explain how each one contributes to the defense.*

6. **Capabilities and their Security Implications:**
   * **Discussion:**
     * What are Linux capabilities and how do they relate to container security?
     * Why is the principle of least privilege especially important for capabilities?
     * Common capabilities and their security implications:
       * `NET_ADMIN`: Allows network configuration changes
       * `SYS_ADMIN`: Provides a wide range of administrative capabilities
       * `SYS_PTRACE`: Allows process tracing/debugging
       * `NET_BIND_SERVICE`: Allows binding to privileged ports (<1024)

   * **Testing Capability Restrictions:**
     * Deploy a pod with restricted capabilities and attempt to perform privileged operations:
       ```bash
       kubectl exec -it secure-pod -n pss-restricted -- bash -c "apt-get update"
       ```
     * Observe the permission denied errors

**🚀 Challenge Task 🚀**
*Analyze an existing application in your environment and create a least-privilege security context configuration. Start by dropping ALL capabilities and running as non-root, then identify only the specific capabilities and permissions the application needs to function. Document how you would test this configuration to ensure functionality while maintaining security.*

7. **Clean up:**
   ```bash
   kubectl delete -f pod-security.yaml
   kubectl delete pod secure-pod -n pss-restricted
   ```

