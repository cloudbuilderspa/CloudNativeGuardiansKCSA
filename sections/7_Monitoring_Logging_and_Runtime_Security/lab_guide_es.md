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

**✨ Punto de Predicción ✨**
*Si un atacante crea exitosamente un nuevo `ClusterRoleBinding` que le otorga privilegios de `cluster-admin`, ¿qué regla en el `audit-policy-sample.yaml` de ejemplo registraría este evento y con qué nivel de detalle?*

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

**✅ Punto de Verificación ✅**
*Basándote en los campos observados (o comprensión conceptual), ¿qué campo específico del registro de auditoría sería más crítico para determinar *qué usuario o cuenta de servicio* inició una solicitud API potencialmente maliciosa (por ejemplo, eliminar un Secret crítico)?*

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   Los registros de auditoría son una fuente principal para detectar actividad API no autorizada.
    *   Una política de auditoría bien definida es esencial para capturar eventos significativos sin ruido excesivo.
    *   Los registros deben almacenarse de forma segura y revisarse o analizarse regularmente por sistemas automatizados.

**🚀 Tarea de Desafío 🚀**
*Imagina que tu política de auditoría está configurada para registrar eventos de `pods/exec` solo a nivel `Metadata`. Un atacante obtiene acceso a un pod en ejecución y usa `kubectl exec` en él para ejecutar comandos maliciosos. ¿Qué información crucial sobre las acciones del atacante *dentro del pod* faltaría en los registros de auditoría con esta política, y qué nivel de auditoría se necesitaría para capturarla?*

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

**✨ Punto de Predicción ✨**
*Antes de ver los registros, ¿qué entrada de registro específica de los comandos de `sample-logging-app` anticipas que sería la *más accionable* para que un equipo de operaciones de seguridad investigue primero, y por qué?*

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

**✅ Punto de Verificación ✅**
*De los registros de ejemplo, si fueras a implementar un registro estructurado (por ejemplo, JSON), enumera tres pares clave-valor que definitivamente incluirías para el evento "Usuario 'bob' falló intento de inicio de sesión" para que sea fácilmente consultable en un SIEM.*

4.  **Limpieza:**
    ```bash
    kubectl delete pod sample-logging-app -n runtime-lab
    # rm logging-app-pod.yaml (si se guardó)
    ```

**🚀 Tarea de Desafío 🚀**
*Muchas aplicaciones registran en stdout/stderr, que luego son recolectados por el runtime del contenedor. Describe una ventaja y una desventaja de este enfoque en comparación con una aplicación que escribe sus registros directamente en un archivo de registro dedicado dentro del sistema de archivos del contenedor.*

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

**✨ Punto de Predicción ✨**
*Cuando ejecutas `kubectl top pod cpu-hog`, ¿qué esperas ver con respecto a su uso de CPU en relación con su límite de CPU definido de `100m` (100 milicores)? ¿Será exactamente `100m`, ligeramente menos, o podría parecer más alto momentáneamente?*

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

**✅ Punto de Verificación ✅**
*Si el pod `cpu-hog` *no* tuviera un límite de CPU definido en su manifiesto y comenzara a consumir CPU excesiva, ¿qué mecanismo en Kubernetes intentaría finalmente detenerlo o evitar que afecte a otros componentes críticos del sistema en el nodo? (Pista: Piensa en la estabilidad del nodo).*

4.  **Limpieza:**
    ```bash
    kubectl delete pod cpu-hog -n runtime-lab
    # rm cpu-hog-pod.yaml (si se guardó)
    ```

**🚀 Tarea de Desafío 🚀**
*Además de `kubectl top`, nombra otra forma nativa de Kubernetes (por ejemplo, un subcomando de `kubectl` o un recurso API) que podrías usar para obtener métricas de consumo de recursos actuales o históricas para un Pod o Nodo. ¿Cuál es una limitación de `kubectl top` para el análisis histórico?*

## Ejercicio 4: Simulación de Respuesta Básica a Incidentes: Aislamiento de un Pod

**Objetivo:** Comprender cómo usar Network Policies (Políticas de Red) para la contención básica de incidentes.

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

**✨ Punto de Predicción ✨**
*Antes de aplicar la NetworkPolicy `isolate-my-app-pod.yaml`, ¿cuál es el comportamiento de red predeterminado dentro del namespace `runtime-lab` que permite a `attacker-sim` conectarse a `my-app-pod`?*

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

**✅ Punto de Verificación ✅**
*La NetworkPolicy aplicada tiene un `ingress: []` y `egress: []` vacíos (implícitamente, al no definir ninguna regla). ¿Por qué esto bloquea efectivamente todo el tráfico, en lugar de permitir todo el tráfico? ¿Qué parte específica de la especificación de la API de NetworkPolicy causa este comportamiento?*

5.  **Discusión:**
    *   ¿Cómo ayuda esta Network Policy a contener un incidente potencial que involucre a `my-app-pod`? (Previene el movimiento lateral desde el Pod y la exfiltración/comunicación C2 hacia el exterior).
    *   ¿Qué otros comandos `kubectl` formarían parte de una respuesta inicial para investigar el `my-app-pod` "comprometido" una vez aislado? (`kubectl logs my-app-pod`, `kubectl describe pod my-app-pod`, potencialmente `kubectl exec` si se considera seguro y necesario para análisis forense en vivo).
    *   ¿Qué hace `kubectl cordon <nombre-del-nodo>` y por qué podría usarse en este escenario?

**🚀 Tarea de Desafío 🚀**
*Imagina que quieres permitir que el `my-app-pod` aislado *solo* realice conexiones de egreso a un servidor DNS interno específico (por ejemplo, `kube-dns.kube-system.svc.cluster.local` en el puerto UDP 53) para registro o diagnósticos, pero aún así bloquear todo el resto del tráfico de ingreso y egreso. ¿Cómo modificarías la NetworkPolicy `isolate-my-app-pod.yaml` para lograr esto? Proporciona el fragmento YAML relevante para la regla de `egress`.*

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
          desc: A shell was spawned in a container with an attached terminal. # Traducción: Se generó un shell en un contenedor con una terminal adjunta.
          condition: evt.type = execve and evt.dir = < and proc.tty != 0 and container.id != host and proc.name in (bash, sh, zsh, ksh, fish, dash, tcsh, csh)
          output: "Shell spawned in a container (user=%user.name container_id=%container.id container_name=%container.name image=%container.image.repository proc_name=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty)" # Traducción: Shell generado en un contenedor (...)
          priority: WARNING
        ```
    *   **Regla 2: Escritura debajo del directorio raíz sensible**
        ```yaml
        - rule: Write below root dir
          desc: An attempt to write to a file below /root # Traducción: Intento de escribir en un archivo debajo de /root
          condition: evt.type = open and evt.dir = < and fd.name startswith /root and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)
          output: "File created/modified below /root by (user=%user.name command=%proc.cmdline file=%fd.name)" # Traducción: Archivo creado/modificado debajo de /root por (...)
          priority: ERROR
        ```
    *   **Regla 3: Conexión de red saliente inesperada**
        ```yaml
        - rule: Unexpected outbound connection
          desc: An outbound network connection was made from a container to an unexpected destination or port. # Traducción: Se realizó una conexión de red saliente desde un contenedor a un destino o puerto inesperado.
          condition: syscall.type = connect and evt.dir = > and fd.typechar = 4 and fd.sip != private_ipv4_ चाँडै and not trusted_connection
          # 'trusted_connection' sería una macro que define conexiones permitidas
          output: "Unexpected outbound connection (container=%container.name image=%container.image.repository connection=%fd.name)" # Traducción: Conexión saliente inesperada (...)
          priority: NOTICE
        ```

**✨ Punto de Predicción ✨**
*Considerando la dependencia de Falco de las llamadas al sistema, si un atacante utiliza una técnica de ataque puramente en memoria dentro de un proceso comprometido (por ejemplo, inyección de código que no genera inmediatamente nuevos procesos ni abre conexiones de red), ¿cómo podría esto desafiar las capacidades de detección de Falco basadas en estas reglas de ejemplo?*

2.  **Discusión:**
    *   Para cada regla:
        *   ¿Qué tipo de actividad maliciosa o sospechosa está tratando de detectar?
        *   ¿Por qué es importante detectar esta actividad para la seguridad en tiempo de ejecución?
    *   ¿Cómo obtiene Falco (conceptualmente) la información para evaluar estas reglas? (Principalmente observando llamadas al sistema (syscalls) realizadas por procesos, ya sea a través de un módulo del kernel o eBPF. También puede ingerir registros de auditoría de Kubernetes).
    *   ¿Qué acciones podría tomar una organización cuando Falco genera una alerta para una de estas reglas? (Investigar, aislar, remediar).

**✅ Punto de Verificación ✅**
*Las reglas de Falco a menudo incluyen `macros` (como `trusted_connection` en la Regla 3, que no está completamente definida en el fragmento). ¿Por qué son cruciales las macros para escribir reglas de Falco efectivas y mantenibles, especialmente en entornos complejos con muchas variaciones legítimas de comportamiento?*

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   Las herramientas de seguridad en tiempo de ejecución proporcionan visibilidad sobre el comportamiento real de las cargas de trabajo.
    *   La detección basada en reglas es efectiva para patrones maliciosos conocidos.
    *   Comprender qué monitorizan estas herramientas (syscalls, red, acceso a archivos) es clave para apreciar su valor.

**🚀 Tarea de Desafío 🚀**
*Además de la detección basada en reglas como la de Falco, ¿cuál es otro enfoque o tecnología común utilizado por las herramientas de seguridad en tiempo de ejecución para detectar comportamientos anómalos o maliciosos en contenedores o cargas de trabajo de Kubernetes? Describe brevemente en qué se diferencia de la detección estática basada en reglas.*

Esta guía de laboratorio debería darle una mejor comprensión práctica y conceptual de la monitorización, el registro y la seguridad en tiempo de ejecución en Kubernetes. Recuerde aplicar siempre estos conceptos dentro del contexto de los requisitos de seguridad específicos y la tolerancia al riesgo de su organización.
