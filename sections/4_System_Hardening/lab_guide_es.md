# Guía de Laboratorio: Modelo de Amenaza de Kubernetes y Fortalecimiento (Hardening) del Sistema

Esta guía de laboratorio proporciona ejercicios para ayudarle a comprender e identificar aspectos del Modelo de Amenaza de Kubernetes y consideraciones para el fortalecimiento del sistema. El enfoque está en la inspección y el análisis usando `kubectl`, en lugar de simular ataques. Estos ejercicios están diseñados para un nivel de comprensión KCSA.

**Nota:** Asegúrese de tener un namespace para pruebas (por ejemplo, `threat-lab-ns`) o cree uno: `kubectl create namespace threat-lab-ns`. Recuerde limpiar los recursos después de completar los laboratorios.

## Ejercicio 1: Identificación de Configuraciones de Pod Riesgosas

**Objetivo:** Identificar configuraciones de Pod que podrían presentar riesgos de seguridad.

**Instrucciones:**

1.  **Revisar un Manifiesto de Pod con un Volumen `hostPath` Riesgoso:**
    *   Considere el siguiente manifiesto (`risky-hostpath-pod.yaml` - no lo aplique todavía, solo revíselo):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: risky-hostpath-pod
          namespace: threat-lab-ns # Asumiendo que este namespace existe
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
              path: /var/run/docker.sock # Montando el socket de Docker
        ```
    *   **Discusión:**
        *   ¿Cuál es la amenaza potencial si este Pod se despliega y se compromete? (Un atacante podría controlar el daemon de Docker en el nodo, lo que llevaría al compromiso del nodo).
        *   ¿Qué nivel de Pod Security Standard (PSS) probablemente evitaría esto? (`Baseline` y `Restricted` deberían prevenirlo).
    *   **Nota de Seguridad:** Montar rutas sensibles del host como el socket de Docker, `/etc`, o `/` es extremadamente peligroso.

2.  **Revisar un Manifiesto de Pod con `privileged: true`:**
    *   Considere (`privileged-example-pod.yaml` - solo revisión):
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
    *   **Discusión:**
        *   ¿Qué capabilities tiene un Pod privilegiado? (Casi todas las capabilities del host, omite muchos mecanismos de seguridad).
        *   ¿Por qué es esto un riesgo significativo? (Fácil compromiso del nodo si el contenedor es vulnerado).
    *   **Nota de Seguridad:** Evite los Pods privilegiados a menos que sea absolutamente necesario para tareas a nivel de sistema y solo con extrema precaución y otros controles compensatorios.

3.  **Revisar un Manifiesto de Pod con `securityContext` Débil:**
    *   Considere (`weak-sctx-pod.yaml` - solo revisión):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: weak-sctx-pod
          namespace: threat-lab-ns
        spec:
          containers:
          - name: main
            image: nginx # Se ejecuta como root por defecto
            command: ["sleep", "3600"]
            # No se especifica securityContext, o uno que permite:
            # securityContext:
            #   runAsUser: 0 # Ejecutándose explícitamente como root
            #   allowPrivilegeEscalation: true
        ```
    *   **Discusión:**
        *   ¿Cuáles son los riesgos de ejecutarse como root en un contenedor por defecto? (Permisos más amplios si el contenedor es comprometido).
        *   ¿Qué implica `allowPrivilegeEscalation: true` (predeterminado si no se establece)? (Un proceso puede obtener más privilegios que su padre).
    *   **Nota de Seguridad:** Siempre defina un `securityContext` para aplicar el menor privilegio: `runAsNonRoot: true`, `runAsUser` (distinto de cero), `allowPrivilegeEscalation: false`, elimine `capabilities` innecesarias.

## Ejercicio 2: Análisis de RBAC para Posible Escalada de Privilegios

**Objetivo:** Identificar configuraciones RBAC que podrían ser abusadas para la escalada de privilegios (sin realizar la escalada).

**Instrucciones:**

1.  **Crear un Namespace de Prueba, ServiceAccount, Role y RoleBinding:**
    ```bash
    kubectl create namespace rbac-escalation-lab
    kubectl create serviceaccount privesc-sa -n rbac-escalation-lab
    ```
    *   Crear `escalation-role.yaml`:
        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: rbac-escalation-lab
          name: escalation-potential-role
        rules:
        # Regla 1: Permiso para crear rolebindings en su propio namespace
        - apiGroups: ["rbac.authorization.k8s.io"]
          resources: ["rolebindings"]
          verbs: ["create"]
        # Regla 2: Permiso para usar el verbo 'passimpersonate' sobre un usuario específico (ej., un usuario privilegiado)
        # Para este laboratorio, solo lo listaremos; vincular passimpersonate es más complejo de configurar de forma segura.
        # - apiGroups: [""]
        #   resources: ["users"]
        #   verbs: ["impersonate"]
        #   resourceNames: ["admin-user"] # Usuario de ejemplo
        # Regla 3: Permiso para crear pods (podría usarse para montar información sensible o usar SA privilegiada)
        - apiGroups: [""]
          resources: ["pods"]
          verbs: ["create", "list"]
        ```
    *   Aplicar el Role: `kubectl apply -f escalation-role.yaml`
    *   Vincular la ServiceAccount a este Role:
        ```bash
        kubectl create rolebinding privesc-sa-binding \
          --role=escalation-potential-role \
          --serviceaccount=rbac-escalation-lab:privesc-sa \
          -n rbac-escalation-lab
        ```

2.  **Usar `kubectl auth can-i` para Verificar Permisos:**
    ```bash
    # ¿Puede la SA crear rolebindings en su namespace?
    kubectl auth can-i create rolebindings --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab

    # ¿Puede la SA crear pods en su namespace?
    kubectl auth can-i create pods --as=system:serviceaccount:rbac-escalation-lab:privesc-sa -n rbac-escalation-lab
    ```

3.  **Discusión:**
    *   Si `privesc-sa` puede crear `rolebindings` en su namespace, ¿cómo podría escalar sus privilegios? (Podría vincularse a sí misma, o a otra SA que controle, a un Role más poderoso dentro de ese namespace, potencialmente hasta `admin` para ese namespace).
    *   Si `privesc-sa` puede crear Pods, ¿cómo podría abusarse de esto si no está restringido adicionalmente por PSS/PSA? (Podría crear un Pod que use una SA muy privilegiada de *otro* namespace si esa SA no está restringida, o un Pod que monte hostPaths, etc.)
    *   Si una SA tuviera `passimpersonate` para un usuario `cluster-admin`, ¿qué permitiría eso? (La SA podría actuar como `cluster-admin`, obteniendo control total del clúster).
    *   **Nota de Seguridad:** Permisos como `create rolebindings`, `create clusterrolebindings`, `passimpersonate`, o derechos amplios de creación de Pods son altamente sensibles y deben controlarse estrictamente.

4.  **Limpieza:**
    ```bash
    kubectl delete namespace rbac-escalation-lab
    rm escalation-role.yaml
    ```

## Ejercicio 3: Exploración de Límites de Confianza y Segmentación de Red

**Objetivo:** Observar el comportamiento de red predeterminado y el efecto de las Network Policies.

**Instrucciones:**

1.  **Crear Dos Namespaces de Prueba y Desplegar Pods:**
    ```bash
    kubectl create namespace netpol-ns1
    kubectl create namespace netpol-ns2

    kubectl run web-ns1 --image=nginx -n netpol-ns1 --labels=app=web
    kubectl run web-ns2 --image=nginx -n netpol-ns2 --labels=app=web
    ```
    *   Esperar a que los Pods estén en ejecución:
        ```bash
        kubectl get pods -n netpol-ns1 -w
        kubectl get pods -n netpol-ns2 -w
        ```

2.  **Intentar Comunicación Entre Pods en Diferentes Namespaces:**
    *   Obtener IP de `web-ns2`: `POD_NS2_IP=$(kubectl get pod web-ns2 -n netpol-ns2 -o jsonpath='{.status.podIP}')`
    *   Ejecutar `exec` en `web-ns1` e intentar hacer `curl` a `web-ns2`:
        ```bash
        kubectl exec -it web-ns1 -n netpol-ns1 -- curl --connect-timeout 2 -I $POD_NS2_IP
        ```
    *   **Resultado Esperado:** Por defecto, la comunicación debería tener éxito. Esto muestra que los namespaces por sí mismos no son límites de aislamiento de red.
    *   **Nota de Seguridad:** Esto ilustra un modelo de red plano sin Network Policies.

3.  **Aplicar una Política de Ingress de Denegación por Defecto a `netpol-ns2`:**
    *   Crear `deny-all-ingress-ns2.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-all-ingress
          namespace: netpol-ns2
        spec:
          podSelector: {} # Aplicar a todos los pods en netpol-ns2
          policyTypes:
          - Ingress
        ```
    *   Aplicar: `kubectl apply -f deny-all-ingress-ns2.yaml`

4.  **Re-probar la Comunicación desde `web-ns1` a `web-ns2`:**
    ```bash
    kubectl exec -it web-ns1 -n netpol-ns1 -- curl --connect-timeout 2 -I $POD_NS2_IP
    ```
    *   **Resultado Esperado:** La comunicación ahora debería **fallar** (timeout).
    *   **Discusión:** ¿Cómo demuestra esto un límite de confianza aplicado por una Network Policy? (El tráfico de `netpol-ns1` ya no es confiable por defecto para entrar en `netpol-ns2`). Esto ayuda a mitigar el movimiento lateral.

5.  **Limpieza:**
    ```bash
    kubectl delete namespace netpol-ns1
    kubectl delete namespace netpol-ns2
    rm deny-all-ingress-ns2.yaml
    ```

## Ejercicio 4: Simulación de Escenarios de Acceso a Datos Sensibles (Conceptual)

**Objetivo:** Comprender cómo RBAC controla el acceso a Secrets y la importancia del cifrado de etcd.

**Instrucciones:**

1.  **Crear un Namespace y un Secret:**
    ```bash
    kubectl create namespace secret-access-lab
    kubectl create secret generic mysecret -n secret-access-lab --from-literal=secretdata='muyconfidencial'
    ```

2.  **Crear Dos ServiceAccounts:**
    ```bash
    kubectl create serviceaccount sa-no-access -n secret-access-lab
    kubectl create serviceaccount sa-with-access -n secret-access-lab
    ```

3.  **Crear un Role y RoleBinding para que `sa-with-access` lea `mysecret`:**
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
          resourceNames: ["mysecret"] # Secret específico
          verbs: ["get"]
        ```
    *   Aplicar Role: `kubectl apply -f secret-reader-role.yaml`
    *   Vincular `sa-with-access`:
        ```bash
        kubectl create rolebinding sa-with-access-secret-reader-binding \
          --role=secret-reader \
          --serviceaccount=secret-access-lab:sa-with-access \
          -n secret-access-lab
        ```

4.  **Análisis Conceptual del Acceso:**
    *   **Pod con `sa-no-access`:**
        *   Si desplegara un Pod usando `sa-no-access`, e intentara usar su token para `kubectl get secret mysecret -n secret-access-lab`, ¿qué sucedería? (Sería denegado por RBAC).
        *   Si intentara montar `mysecret` como un volumen, ¿qué sucedería? (Al Kubelet, actuando en nombre del Pod a través de su token de SA, probablemente se le denegaría el permiso por parte del API server para obtener el secret para el montaje, por lo que el Pod podría fallar al iniciarse).
    *   **Pod con `sa-with-access`:**
        *   Si desplegara un Pod usando `sa-with-access` y montara `mysecret` como un volumen, tendría éxito. El Kubelet (usando el token de la SA) estaría autorizado para obtener el Secret.
        *   El Pod podría entonces leer los datos del secret desde los archivos montados.

5.  **Discusión sobre el Cifrado de Etcd:**
    *   ¿Dónde se almacenan los Kubernetes Secrets? (En `etcd`).
    *   Por defecto, ¿están cifrados en `etcd`? (No, solo codificados en base64).
    *   ¿Por qué es crítico habilitar el cifrado en reposo para `etcd` para proteger los Secrets? (Protege los datos de los Secrets incluso si un atacante obtiene acceso a las copias de seguridad de `etcd` o a los archivos de datos brutos de `etcd`).
    *   **Nota de Seguridad:** RBAC controla el acceso *API* a los Secrets. El cifrado de Etcd protege los Secrets *en reposo*. Ambos son necesarios.

6.  **Limpieza:**
    ```bash
    kubectl delete namespace secret-access-lab
    rm secret-reader-role.yaml
    ```

## Ejercicio 5: Reconocimiento de Vectores de Denegación de Servicio (DoS) (Conceptual)

**Objetivo:** Identificar configuraciones o escenarios que podrían llevar a DoS.

**Instrucciones:**

1.  **Revisar un Manifiesto de Pod sin Límites de Recursos:**
    *   Considere (`no-limits-pod.yaml` - solo revisión):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: no-limits-pod
        spec:
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "while true; do echo consumiendo...; done"] # Ejemplo de un bucle ocupado
            # No se definen resources: { limits: ..., requests: ...}
        ```
    *   **Discusión:**
        *   ¿Qué podría suceder si se despliegan muchos de estos Pods en un nodo sin límites de recursos? (Agotamiento de CPU/memoria en el nodo, afectando a otros Pods y la estabilidad del Kubelet - un DoS de "vecino ruidoso").
        *   ¿Cómo ayudan los objetos `LimitRange` y `ResourceQuota` a mitigar esto? (`LimitRange` establece límites/solicitudes predeterminados para Pods en un namespace si no se especifican; `ResourceQuota` establece límites generales de consumo de recursos para un namespace).
    *   **Nota de Seguridad:** Siempre establezca solicitudes y límites de recursos para sus cargas de trabajo.

2.  **Discutir Sobrecarga del API Server (Conceptual):**
    *   **Escenario:** Imagine un script (o un componente comprometido) realizando miles de solicitudes API por segundo al API Server.
    *   **Impacto:** Esto podría sobrecargar el API Server, haciéndolo lento o no responsivo para usuarios legítimos y componentes del plano de control.
    *   **Mitigación:**
        *   El API Server tiene limitación de tasa (rate limiting) incorporada (aunque los valores predeterminados podrían necesitar ajustes para clústeres muy grandes o casos de abuso específicos).
        *   Autenticación y autorización adecuadas para evitar que clientes no autorizados realicen solicitudes excesivas.
        *   Monitorización del rendimiento del API Server y las latencias de las solicitudes.
    *   **Nota de Seguridad:** Proteger el API Server de DoS es crucial para la disponibilidad del clúster.

## Ejercicio 6: Consideración de Técnicas de Persistencia (Conceptual)

**Objetivo:** Pensar en cómo los atacantes podrían lograr persistencia en un clúster de Kubernetes.

**Instrucciones:**

1.  **Revisar un Manifiesto de CronJob:**
    *   Considere (`example-cronjob.yaml` - solo revisión):
        ```yaml
        apiVersion: batch/v1
        kind: CronJob
        metadata:
          name: example-cronjob
        spec:
          schedule: "*/5 * * * *" # Cada 5 minutos
          jobTemplate:
            spec:
              template:
                spec:
                  restartPolicy: OnFailure
                  containers:
                  - name: main
                    image: busybox
                    command: ["echo", "Hola desde CronJob"]
        ```
    *   **Discusión:**
        *   Si un atacante tiene permisos RBAC para crear CronJobs en un namespace, ¿cómo podría usar esto para persistencia? (Podrían programar un CronJob para ejecutar un Pod con una imagen o comando malicioso periódicamente, por ejemplo, para restablecer un shell inverso o exfiltrar datos).
    *   **Mitigación:** Restringir los permisos para crear/gestionar CronJobs usando RBAC. Monitorear la creación de CronJobs.

2.  **Discutir Imágenes con Puertas Traseras (Backdoored) en Deployments:**
    *   **Escenario:** Un atacante logra introducir una imagen de contenedor con puerta trasera (por ejemplo, que contenga un binario de shell inverso) en la plantilla de Pod de un Deployment.
    *   **Persistencia:** Cada vez que el Deployment escale o se reinicie un Pod, se creará un nuevo Pod con la imagen con puerta trasera, restableciendo potencialmente el acceso del atacante.
    *   **Mitigación:**
        *   Prácticas robustas de seguridad de imágenes (escaneo, registros confiables, firma de imágenes - cubierto en Seguridad de la Cadena de Suministro).
        *   RBAC para restringir quién puede modificar Deployments.
        *   GitOps con validación de manifiestos y revisión antes de aplicar cambios.
    *   **Nota de Seguridad:** La persistencia a través de controladores de carga de trabajo como Deployments o DaemonSets es efectiva para los atacantes porque Kubernetes intenta activamente mantener estas cargas de trabajo en ejecución.

**Nota de Limpieza:** Recuerde eliminar cualquier namespace u otros recursos de prueba creados si no se han eliminado ya en los ejercicios individuales.

