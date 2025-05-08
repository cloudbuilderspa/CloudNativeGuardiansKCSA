# Guía de Laboratorio: Monitorización, Registro (Logging) y Seguridad en Tiempo de Ejecución

Esta guía de laboratorio proporciona ejercicios para ayudarle a comprender aspectos clave de la monitorización, el registro y la seguridad en tiempo de ejecución en Kubernetes. El enfoque está en la comprensión conceptual y el uso de `kubectl` para inspección e interacción básica, adecuado para un nivel de conocimiento KCSA.

**Nota:** Cree un namespace de prueba para estos ejercicios si es necesario: `kubectl create namespace runtime-lab`. Recuerde limpiar los recursos después.

## Ejercicio 1: Inspección de Registros de Auditoría de Kubernetes (Conceptual e Interacción Básica)

**Objetivo:** Comprender qué capturan los registros de auditoría de Kubernetes y su importancia para la seguridad.

**Instrucciones:**

1.  **Tarea 1 (Conceptual): Revisar Fragmento de Política de Auditoría y Flags del API Server**
    *   Considere este fragmento de un archivo de política de auditoría de Kubernetes:
        ```yaml
        # audit-policy-sample.yaml
        apiVersion: audit.k8s.io/v1
        kind: Policy
        rules:
        # Registrar comandos exec en pods a nivel RequestResponse
        - level: RequestResponse
          resources:
          - group: "" # core
            resources: ["pods/exec"]
        # Registrar creaciones, eliminaciones y actualizaciones de Secrets
        - level: RequestResponse
          resources:
          - group: "" # core
            resources: ["secrets"]
          verbs: ["create", "delete", "update", "patch"]
        # Registrar cambios de RBAC
        - level: RequestResponse
          groups: ["rbac.authorization.k8s.io"]
        # Registrar otras solicitudes a nivel Metadata
        - level: Metadata
        ```
    *   **Discusión:**
        *   ¿Qué flags del API server se utilizan para habilitar la auditoría y especificar el archivo de política? (Típicamente `--audit-log-path=/var/log/kubernetes/audit.log` y `--audit-policy-file=/etc/kubernetes/audit-policy.yaml`).
        *   En la política de ejemplo, ¿por qué se registran las modificaciones de `pods/exec` y `secrets` a nivel `RequestResponse`? (Para capturar todos los detalles de operaciones potencialmente de alto riesgo).
        *   ¿Por qué se registran otras solicitudes a nivel `Metadata`? (Para reducir el volumen de registros sin dejar de capturar información esencial del evento).

2.  **Tarea 2 (Si es posible): Encontrar un Evento en los Registros de Auditoría**
    *   **Nota:** El acceso a los registros de auditoría sin procesar depende en gran medida de la configuración de su clúster de Kubernetes (Minikube, Kind, servicio de nube gestionado). Para Minikube, podría hacer `minikube ssh` y encontrar los registros típicamente en `/var/log/kubernetes/audit.log` o similar, si está habilitado.
    *   Si es accesible:
        1.  Realice una acción simple con `kubectl`, por ejemplo, `kubectl get pods -n kube-system`.
        2.  Intente usar `tail` o `grep` en el archivo de registro de auditoría para este evento. Busque entradas que contengan su nombre de usuario (de `kubectl config view`), el verbo `get` y el recurso `pods`.
        ```bash
        # Dentro de la VM de Minikube o donde estén los registros de auditoría:
        # sudo grep '"verb":"get"' /var/log/kubernetes/audit.log | grep '"resource":"pods"' | tail -n 5
        ```
    *   **Observar (incluso conceptualmente):**
        *   `user.username`: Quién realizó la solicitud.
        *   `verb`: La acción (por ejemplo, `get`, `create`, `delete`).
        *   `objectRef.resource`: El tipo de recurso (por ejemplo, `pods`, `secrets`).
        *   `objectRef.namespace`: El namespace.
        *   `responseStatus.code`: El código de estado HTTP de la respuesta.
    *   **Discusión:** ¿Por qué son cruciales los registros de auditoría para la monitorización de seguridad, la investigación de incidentes y el cumplimiento?

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   Los registros de auditoría son una fuente principal para detectar actividad API no autorizada.
    *   Una política de auditoría bien definida es esencial para capturar eventos significativos sin ruido excesivo.
    *   Los registros deben almacenarse de forma segura y revisarse o analizarse regularmente por sistemas automatizados.

## Ejercicio 2: Análisis de Registros de Aplicación para Eventos de Seguridad

**Objetivo:** Reconocer información relevante para la seguridad en los registros de aplicación y comprender las mejores prácticas de logging.

**Instrucciones:**

1.  **Desplegar un Pod de Aplicación de Logging de Ejemplo:**
    *   Crear `logging-app-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: sample-logging-app
          namespace: runtime-lab # Use su namespace de prueba
        spec:
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", 
                      "echo \"INFO: $(date) Servicio iniciado correctamente.\"; \
                       sleep 5; \
                       echo \"INFO: $(date) Usuario 'alice' inició sesión desde IP 10.1.2.3\"; \
                       sleep 5; \
                       echo \"WARN: $(date) Usuario 'bob' falló intento de inicio de sesión (contraseña inválida) desde IP 192.168.1.100\"; \
                       sleep 5; \
                       echo \"INFO: $(date) Registro de datos ID '789' accedido por usuario 'alice'\"; \
                       sleep 5; \
                       echo \"ERROR: $(date) Falló procesamiento de pago para transacción 'xyz123': Fondos insuficientes\"; \
                       sleep 600"]
        ```
    *   Aplicar: `kubectl apply -f logging-app-pod.yaml -n runtime-lab`

2.  **Ver Registros de Aplicación:**
    ```bash
    kubectl logs sample-logging-app -n runtime-lab
    # Use -f para seguimiento en vivo: kubectl logs -f sample-logging-app -n runtime-lab
    ```

3.  **Análisis y Discusión:**
    *   ¿Qué entradas de registro son relevantes para la seguridad? (por ejemplo, "Usuario 'alice' inició sesión", "Usuario 'bob' falló intento de inicio de sesión").
    *   ¿Qué acciones podría tomar un analista de seguridad basándose en múltiples registros de "falló intento de inicio de sesión" para el usuario 'bob' desde varias IPs? (Investigar posible ataque de fuerza bruta, bloquear temporalmente la cuenta, alertar al usuario).
    *   ¿Cómo facilitaría el registro estructurado (por ejemplo, formato JSON: `{"timestamp": "...", "level": "INFO", "user": "alice", "action": "login", "source_ip": "10.1.2.3"}`) el análisis de estos registros por un SIEM o una herramienta automatizada en comparación con texto plano?
    *   ¿Qué información sensible *no* debería estar presente en estos registros (por ejemplo, contraseñas reales, tokens de sesión completos)?

4.  **Limpieza:**
    ```bash
    kubectl delete pod sample-logging-app -n runtime-lab
    # rm logging-app-pod.yaml (si se guardó)
    ```

## Ejercicio 3: Monitorización Básica de Recursos para Anomalías

**Objetivo:** Usar `kubectl top` para observar el uso de recursos y discutir sus implicaciones de seguridad.

**Instrucciones:**

1.  **Desplegar un Pod Diseñado para Consumir CPU (si no está ya en su namespace de prueba):**
    *   Crear `cpu-hog-pod.yaml`:
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
            command: ["sh", "-c", "while true; do true; done"] # Bucle ocupado básico
            resources:
              requests:
                cpu: "10m" # Solicitud pequeña para asegurar que se programe
              limits:
                cpu: "100m" # Límite para evitar sobrecargar clústeres de prueba pequeños
        ```
    *   Aplicar: `kubectl apply -f cpu-hog-pod.yaml -n runtime-lab`
    *   Esperar a que se ejecute: `kubectl get pod cpu-hog -n runtime-lab -w`

2.  **Observar Uso de Recursos:**
    *   Obtener el nombre del nodo donde `cpu-hog` se está ejecutando:
        ```bash
        NODE_NAME=$(kubectl get pod cpu-hog -n runtime-lab -o jsonpath='{.spec.nodeName}')
        echo "Pod cpu-hog se está ejecutando en el nodo: $NODE_NAME"
        ```
    *   Monitorizar uso de CPU del Pod:
        ```bash
        kubectl top pod cpu-hog -n runtime-lab
        ```
    *   Monitorizar uso de CPU y Memoria del Nodo:
        ```bash
        kubectl top node $NODE_NAME
        ```
    *   (Ejecute estos comandos `top` algunas veces para ver el uso).

3.  **Discusión:**
    *   ¿Cómo podría un uso de recursos consistentemente alto o picos inesperados para un Pod indicar un problema de seguridad? (por ejemplo, malware de criptojacking consumiendo CPU, un ataque DoS causando alta red/CPU, un proceso descontrolado debido a una explotación).
    *   ¿Cómo ayudan los `limits` de recursos (CPU, memoria) definidos en la especificación de un Pod a mitigar el impacto de tales problemas en el nodo y otros Pods? (Restringen el Pod que se comporta mal, evitando que prive de recursos a otras cargas de trabajo).
    *   ¿Qué otras métricas (más allá de CPU/memoria) podrían ser útiles para la monitorización de seguridad? (E/S de red, E/S de disco, número de procesos en ejecución).

4.  **Limpieza:**
    ```bash
    kubectl delete pod cpu-hog -n runtime-lab
    # rm cpu-hog-pod.yaml (si se guardó)
    ```

## Ejercicio 4: Simulación de Respuesta Básica a Incidentes: Aislamiento de un Pod

**Objetivo:** Comprender cómo usar Network Policies para la contención básica de incidentes.

**Instrucciones:**

1.  **Configuración: Desplegar Dos Pods en el Namespace `runtime-lab`:**
    *   `app-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: my-app-pod
          namespace: runtime-lab
          labels:
            app: my-app # Etiqueta importante para la política
        spec:
          containers:
          - name: nginx
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   `attacker-sim-pod.yaml`: (Esto simula otro Pod intentando conectarse)
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
            command: ["sleep", "3600"] # Mantenerlo en ejecución para exec
        ```
    *   Aplicar ambos:
        ```bash
        kubectl apply -f app-pod.yaml -n runtime-lab
        kubectl apply -f attacker-sim-pod.yaml -n runtime-lab
        ```
    *   Esperar a los Pods: `kubectl get pods -n runtime-lab -w`
    *   Obtener IP de `my-app-pod`: `APP_POD_IP=$(kubectl get pod my-app-pod -n runtime-lab -o jsonpath='{.status.podIP}')`

2.  **Verificar Conectividad Inicial:**
    ```bash
    kubectl exec -it attacker-sim -n runtime-lab -- curl --connect-timeout 2 -I $APP_POD_IP
    ```
    *   **Resultado Esperado:** La conexión debería tener éxito (Respuesta HTTP de Nginx).

3.  **Escenario: Se Sospecha que `my-app-pod` está Comprometido. Aislarlo.**
    *   Crear `isolate-my-app-pod.yaml`:
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: isolate-my-app-pod-policy
          namespace: runtime-lab
        spec:
          podSelector:
            matchLabels:
              app: my-app # Selecciona my-app-pod
          policyTypes:
          - Ingress
          - Egress
          # La ausencia de reglas de ingress o egress significa que todo el tráfico está denegado
        ```
    *   Aplicar la política de aislamiento: `kubectl apply -f isolate-my-app-pod.yaml -n runtime-lab`

4.  **Verificar Aislamiento:**
    *   Intentar conexión desde `attacker-sim` a `my-app-pod` nuevamente:
        ```bash
        kubectl exec -it attacker-sim -n runtime-lab -- curl --connect-timeout 2 -I $APP_POD_IP
        ```
        **Resultado Esperado:** La conexión ahora debería **fallar** (timeout).
    *   Intentar conexión saliente desde `my-app-pod` (por ejemplo, a un sitio externo, o incluso `kubernetes.default.svc`):
        ```bash
        kubectl exec -it my-app-pod -n runtime-lab -- curl --connect-timeout 2 -I https://www.google.com
        ```
        **Resultado Esperado:** La conexión debería **fallar** (timeout).

5.  **Discusión:**
    *   ¿Cómo ayuda esta Network Policy a contener un incidente potencial que involucre a `my-app-pod`? (Previene el movimiento lateral desde el Pod y la exfiltración/comunicación C2 hacia el exterior).
    *   ¿Qué otros comandos `kubectl` formarían parte de una respuesta inicial para investigar el `my-app-pod` "comprometido" una vez aislado? (`kubectl logs my-app-pod`, `kubectl describe pod my-app-pod`, potencialmente `kubectl exec` si se considera seguro y necesario para análisis forense en vivo).
    *   ¿Qué hace `kubectl cordon <nombre-del-nodo>` y por qué podría usarse en este escenario?

6.  **Limpieza:**
    ```bash
    kubectl delete namespace runtime-lab
    # rm app-pod.yaml attacker-sim-pod.yaml isolate-my-app-pod.yaml (si se guardaron)
    ```

## Ejercicio 5: Comprensión de Herramientas de Seguridad en Tiempo de Ejecución (Conceptual - Falco)

**Objetivo:** Comprender los tipos de amenazas que una herramienta de seguridad en tiempo de ejecución como Falco puede detectar.

**Instrucciones (Revisión Conceptual):**

1.  **Revisar Reglas de Ejemplo de Falco:**
    *   **Regla 1: Shell generado en un contenedor**
        ```yaml
        - rule: Terminal shell in container
          desc: A shell was spawned in a container with an attached terminal.
          condition: evt.type = execve and evt.dir = < and proc.tty != 0 and container.id != host and proc.name in (bash, sh, zsh, ksh, fish, dash, tcsh, csh)
          output: "Shell spawned in a container (user=%user.name container_id=%container.id container_name=%container.name image=%container.image.repository proc_name=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty)"
          priority: WARNING
        ```
    *   **Regla 2: Escritura debajo del directorio raíz sensible**
        ```yaml
        - rule: Write below root dir
          desc: An attempt to write to a file below /root
          condition: evt.type = open and evt.dir = < and fd.name startswith /root and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)
          output: "File created/modified below /root by (user=%user.name command=%proc.cmdline file=%fd.name)"
          priority: ERROR
        ```
    *   **Regla 3: Conexión de red saliente inesperada**
        ```yaml
        - rule: Unexpected outbound connection
          desc: An outbound network connection was made from a container to an unexpected destination or port.
          condition: syscall.type = connect and evt.dir = > and fd.typechar = 4 and fd.sip != private_ipv4_ चाँडै and not trusted_connection
          # 'trusted_connection' sería una macro que define conexiones permitidas
          output: "Unexpected outbound connection (container=%container.name image=%container.image.repository connection=%fd.name)"
          priority: NOTICE
        ```

2.  **Discusión:**
    *   Para cada regla:
        *   ¿Qué tipo de actividad maliciosa o sospechosa está tratando de detectar?
        *   ¿Por qué es importante detectar esta actividad para la seguridad en tiempo de ejecución?
    *   ¿Cómo obtiene Falco (conceptualmente) la información para evaluar estas reglas? (Principalmente observando llamadas al sistema (syscalls) realizadas por procesos, ya sea a través de un módulo del kernel o eBPF. También puede ingerir registros de auditoría de Kubernetes).
    *   ¿Qué acciones podría tomar una organización cuando Falco genera una alerta para una de estas reglas? (Investigar, aislar, remediar).

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   Las herramientas de seguridad en tiempo de ejecución proporcionan visibilidad sobre el comportamiento real de las cargas de trabajo.
    *   La detección basada en reglas es efectiva para patrones maliciosos conocidos.
    *   Comprender qué monitorizan estas herramientas (syscalls, red, acceso a archivos) es clave para apreciar su valor.

Esta guía de laboratorio debería darle una mejor comprensión práctica y conceptual de la monitorización, el registro y la seguridad en tiempo de ejecución en Kubernetes. Recuerde aplicar siempre estos conceptos dentro del contexto de los requisitos de seguridad específicos y la tolerancia al riesgo de su organización.

