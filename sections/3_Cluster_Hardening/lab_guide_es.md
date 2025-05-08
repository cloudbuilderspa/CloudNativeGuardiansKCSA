# Guía de Laboratorio: Fundamentos de Seguridad de Kubernetes para el Fortalecimiento (Hardening) del Clúster

Esta guía de laboratorio proporciona ejercicios prácticos para reforzar su comprensión de los fundamentos de seguridad de Kubernetes cruciales para el fortalecimiento del clúster. Estos ejercicios se alinean con el conocimiento de nivel KCSA y asumen que usted tiene acceso `kubectl` a un clúster de Kubernetes.

**Nota:** Asegúrese de tener un namespace para pruebas (por ejemplo, `test-hardening-ns`) o cree uno: `kubectl create namespace test-hardening-ns`. Recuerde limpiar los recursos después de completar los laboratorios.

## Ejercicio 1: Configuración de Pod Security Admission (PSA)

**Objetivo:** Comprender y configurar Pod Security Admission para un namespace.

**Instrucciones:**

1.  **Crear un Namespace de Prueba:**
    ```bash
    kubectl create namespace psa-lab
    ```

2.  **Etiquetar el Namespace para el nivel PSS `baseline` (enforce, audit, warn):**
    *   Esta configuración aplicará la política `baseline`, auditará cualquier violación contra la política `baseline` (escribiendo en los registros de auditoría) y advertirá al usuario si una especificación de Pod viola la política `baseline`. Lo configuramos a la última versión disponible.
    ```bash
    kubectl label --overwrite ns psa-lab \
      pod-security.kubernetes.io/enforce=baseline \
      pod-security.kubernetes.io/enforce-version=latest \
      pod-security.kubernetes.io/audit=baseline \
      pod-security.kubernetes.io/audit-version=latest \
      pod-security.kubernetes.io/warn=baseline \
      pod-security.kubernetes.io/warn-version=latest
    ```
    *   Verificar etiquetas: `kubectl get ns psa-lab --show-labels`

3.  **Intentar Desplegar un Pod que Viole la Política `baseline` (Pod Privilegiado):**
    *   Crear `privileged-pod.yaml`:
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
              privileged: true # Esto viola baseline
        ```
    *   Intentar aplicar: `kubectl apply -f privileged-pod.yaml`
    *   **Resultado Esperado:** La creación del Pod debería ser **denegada** debido a la etiqueta `enforce=baseline`. Debería ver un mensaje de error indicando la violación. Si revisa los registros de auditoría (conceptual para este laboratorio), se generaría un evento de auditoría. También se mostraría una advertencia al usuario.
    *   **Nota de Seguridad:** Esto demuestra cómo PSA previene el despliegue de Pods excesivamente privilegiados.

4.  **Intentar Desplegar un Pod que Viole `baseline` (por ejemplo, volumen HostPath):**
    *   Crear `hostpath-pod.yaml`:
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
              path: /var # Montar directorios sensibles del host como /var generalmente está prohibido por baseline
              type: Directory
        ```
    *   Intentar aplicar: `kubectl apply -f hostpath-pod.yaml`
    *   **Resultado Esperado:** La creación del Pod debería ser **denegada**. Los volúmenes `hostPath` para directorios sensibles del host suelen estar restringidos por la política `baseline`.

5.  **Desplegar un Pod Conforme:**
    *   Crear `compliant-pod.yaml`:
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
    *   Aplicar: `kubectl apply -f compliant-pod.yaml`
    *   **Resultado Esperado:** El Pod debería crearse correctamente ya que cumple con PSS `baseline` (y probablemente `restricted`).
    *   Verificar estado: `kubectl get pod -n psa-lab compliant-pod`

6.  **Limpieza:**
    ```bash
    kubectl delete namespace psa-lab
    rm privileged-pod.yaml hostpath-pod.yaml compliant-pod.yaml
    ```

## Ejercicio 2: Configuración de RBAC

**Objetivo:** Practicar la creación y aplicación de roles RBAC para una ServiceAccount.

**Instrucciones:**

1.  **Crear un Namespace para este ejercicio:**
    ```bash
    kubectl create namespace rbac-lab
    ```

2.  **Crear una nueva ServiceAccount:**
    ```bash
    kubectl create serviceaccount my-app-sa -n rbac-lab
    ```

3.  **Crear un Role que otorgue acceso de solo lectura a Pods en el namespace `rbac-lab`:**
    *   Crear `pod-reader-role.yaml`:
        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: rbac-lab
          name: pod-reader
        rules:
        - apiGroups: [""] # Grupo API principal (core)
          resources: ["pods", "pods/log"]
          verbs: ["get", "list", "watch"]
        ```
    *   Aplicar: `kubectl apply -f pod-reader-role.yaml`

4.  **Crear un RoleBinding para vincular la ServiceAccount `my-app-sa` al Role `pod-reader`:**
    ```bash
    kubectl create rolebinding my-app-sa-pod-reader-binding \
      --role=pod-reader \
      --serviceaccount=rbac-lab:my-app-sa \
      -n rbac-lab
    ```
    *   Verificar: `kubectl describe rolebinding my-app-sa-pod-reader-binding -n rbac-lab`

5.  **Desplegar un Pod usando esta ServiceAccount y verificar sus permisos:**
    *   Crear `test-rbac-pod.yaml`:
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
            image: bitnami/kubectl:latest # Imagen con kubectl
            command: ["sleep", "3600"]
        ```
    *   Aplicar: `kubectl apply -f test-rbac-pod.yaml`
    *   Esperar a que el Pod esté en ejecución: `kubectl get pod test-rbac-pod -n rbac-lab -w`
    *   Ejecutar `exec` en el Pod: `kubectl exec -it test-rbac-pod -n rbac-lab -- sh`
    *   Dentro del Pod, intentar listar Pods (debería tener éxito):
        ```sh
        kubectl get pods -n rbac-lab
        ```
    *   Intentar listar Secrets (debería fallar):
        ```sh
        kubectl get secrets -n rbac-lab
        ```
    *   Salir del pod: `exit`
    *   **Resultado Esperado:** El Pod, usando `my-app-sa`, puede listar Pods en `rbac-lab` pero no puede listar Secrets, demostrando los permisos RBAC aplicados.
    *   **Nota de Seguridad:** Este ejercicio demuestra el principio de menor privilegio para las ServiceAccounts.

6.  **Limpieza:**
    ```bash
    kubectl delete namespace rbac-lab
    rm pod-reader-role.yaml test-rbac-pod.yaml
    ```

## Ejercicio 3: Gestión de Secrets

**Objetivo:** Practicar la creación y uso de Kubernetes Secrets en Pods.

**Instrucciones:**

1.  **Crear un Namespace para este ejercicio:**
    ```bash
    kubectl create namespace secrets-lab
    ```

2.  **Crear un Secret genérico (por ejemplo, con un nombre de usuario/contraseña):**
    ```bash
    kubectl create secret generic my-db-credentials \
      --from-literal=username='dbuser' \
      --from-literal=password='S3cr3tP@sswOrd' \
      -n secrets-lab
    ```
    *   Inspeccionar el Secret (nótese que está codificado en base64): `kubectl get secret my-db-credentials -n secrets-lab -o yaml`

3.  **Montar el Secret como archivos en un Pod:**
    *   Crear `secret-file-pod.yaml`:
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
            command: ["sh", "-c", "echo 'Secrets montados. Usuario:'; cat /etc/db-credentials/username; echo 'Contraseña:'; cat /etc/db-credentials/password; sleep 3600"]
            volumeMounts:
            - name: db-creds-volume
              mountPath: "/etc/db-credentials"
              readOnly: true
          volumes:
          - name: db-creds-volume
            secret:
              secretName: my-db-credentials
        ```
    *   Aplicar: `kubectl apply -f secret-file-pod.yaml`
    *   Verificar registros: `kubectl logs secret-file-pod -n secrets-lab`
    *   **Resultado Esperado:** Los registros deberían mostrar el nombre de usuario y la contraseña decodificados, leídos de los archivos montados.
    *   **Nota de Seguridad:** Generalmente se prefiere montar como archivos de solo lectura en lugar de variables de entorno.

4.  **Montar partes del Secret como variables de entorno:**
    *   Crear `secret-env-pod.yaml`:
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
            command: ["sh", "-c", "echo 'Usuario desde env: $DB_USER'; echo 'Contraseña desde env: $DB_PASS'; sleep 3600"]
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
    *   Aplicar: `kubectl apply -f secret-env-pod.yaml`
    *   Verificar registros: `kubectl logs secret-env-pod -n secrets-lab`
    *   **Resultado Esperado:** Los registros deberían mostrar el nombre de usuario y la contraseña de las variables de entorno.
    *   **Discusión:** Comparar las implicaciones de seguridad de los montajes de archivos frente a las variables de entorno (las variables de entorno pueden exponerse más fácilmente a través de registros, procesos hijos o `describe pod`).

5.  **Limpieza:**
    ```bash
    kubectl delete namespace secrets-lab
    rm secret-file-pod.yaml secret-env-pod.yaml
    ```

## Ejercicio 4: Implementación de Network Policy

**Objetivo:** Implementar segmentación de red básica usando Network Policies (Políticas de Red). (Requiere un plugin CNI que admita Network Policies, por ejemplo, Calico, Cilium, Weave).

**Instrucciones:**

1.  **Crear un Namespace para este ejercicio:**
    ```bash
    kubectl create namespace netpol-lab
    ```

2.  **Desplegar dos Pods de servidor web simples (por ejemplo, Nginx) con etiquetas distintas:**
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
    *   Aplicar ambos: `kubectl apply -f pod-a.yaml -f pod-b.yaml`
    *   Esperar a que estén en ejecución. Obtener sus direcciones IP: `kubectl get pods -n netpol-lab -o wide`

3.  **Verificar que los Pods pueden comunicarse inicialmente:**
    *   Ejecutar `exec` en `pod-a` e intentar hacer `curl` a la IP de `pod-b`:
        ```bash
        POD_B_IP=$(kubectl get pod pod-b -n netpol-lab -o jsonpath='{.status.podIP}')
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Resultado Esperado:** La comunicación debería tener éxito (HTTP 200 OK).

4.  **Crear una Network Policy de `default-deny` para Ingress en el namespace `netpol-lab`:**
    *   `default-deny-ingress.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-ingress
          namespace: netpol-lab
        spec:
          podSelector: {} # Selecciona todos los pods
          policyTypes:
          - Ingress
        ```
    *   Aplicar: `kubectl apply -f default-deny-ingress.yaml`

5.  **Verificar que los Pods YA NO PUEDEN comunicarse (para ingress a pod-b):**
    *   Repetir el `curl` desde `pod-a` a `pod-b`:
        ```bash
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Resultado Esperado:** La comunicación ahora debería fallar (timeout o conexión rechazada) porque no se permite explícitamente ningún ingreso a `pod-b`.

6.  **Crear una Network Policy para permitir el ingreso a `pod-b` (rol: backend) desde `pod-a` (rol: frontend) en el puerto 80:**
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
              role: backend # La política se aplica a pod-b
          policyTypes:
          - Ingress
          ingress:
          - from:
            - podSelector:
                matchLabels:
                  app: myapp
                  role: frontend # Permitir desde pod-a
            ports:
            - protocol: TCP
              port: 80
        ```
    *   Aplicar: `kubectl apply -f allow-frontend-to-backend.yaml`

7.  **Verificar que `pod-a` ahora puede comunicarse con `pod-b`, pero otro ingreso sigue denegado:**
    *   Repetir el `curl` desde `pod-a` a `pod-b`:
        ```bash
        kubectl exec -it pod-a -n netpol-lab -- curl -I --connect-timeout 2 $POD_B_IP
        ```
    *   **Resultado Esperado:** La comunicación debería tener éxito nuevamente.
    *   **Nota de Seguridad:** Las Network Policies son esenciales para la microsegmentación y la implementación de un modelo de confianza cero.

8.  **Limpieza:**
    ```bash
    kubectl delete namespace netpol-lab
    rm pod-a.yaml pod-b.yaml default-deny-ingress.yaml allow-frontend-to-backend.yaml
    ```

## Ejercicio 5: Inspección del Registro de Auditoría (Audit Logging) (Conceptual/Si es Posible)

**Objetivo:** Comprender cómo verificar la configuración del registro de auditoría y qué buscar.

**Instrucciones:**

1.  **Discutir Flags del Registro de Auditoría del API Server (Conceptual):**
    *   Si tiene acceso para inspeccionar el manifiesto del API Server (por ejemplo, `minikube ssh` y luego `sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml`), busque flags como:
        *   `--audit-log-path`: Especifica la ruta del archivo para los registros de auditoría.
        *   `--audit-policy-file`: Especifica la ruta al archivo de política de auditoría que define qué registrar.
        *   `--audit-log-maxage`, `--audit-log-maxbackup`, `--audit-log-maxsize`: Flags para la rotación de registros.
    *   **Discusión:** ¿Por qué son importantes estos flags? ¿Qué información controla un archivo de política de auditoría (niveles, etapas)? Consulte `main_concepts_es.md` para detalles sobre la política de auditoría.

2.  **Intentar Encontrar un Evento de Auditoría (Si los registros son accesibles y conoce la ruta):**
    *   Este paso depende en gran medida de la configuración de su clúster. Si usa Minikube y encontró un `--audit-log-path` como `/var/log/kubernetes/audit.log`:
        ```bash
        minikube ssh
        sudo tail -f /var/log/kubernetes/audit.log # O la ruta que encontró
        ```
    *   En otra terminal, realice una acción con `kubectl` (por ejemplo, `kubectl get pods -n kube-system`).
    *   Intente identificar la entrada de registro correspondiente. Busque su nombre de usuario/cliente, el verbo (`get`) y el recurso (`pods`).
    *   **Resultado Esperado (Conceptual):** Obtener una apreciación del detalle y volumen de los registros de auditoría. Comprender que la inspección manual es difícil, lo que resalta la necesidad de herramientas de análisis automatizado.
    *   **Nota de Seguridad:** Los registros de auditoría son su fuente principal para detectar e investigar incidentes de seguridad. Asegúrese de que estén habilitados, configurados correctamente y almacenados de forma segura.

**Nota de Limpieza:** Recuerde eliminar cualquier namespace u otros recursos creados específicamente para estos laboratorios si no se limpian automáticamente al eliminar el namespace.

