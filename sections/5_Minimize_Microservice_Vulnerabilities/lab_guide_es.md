# Guía de Laboratorio: Minimización de Vulnerabilidades en Microservicios

Esta guía de laboratorio ofrece ejercicios prácticos y revisiones conceptuales para ayudarle a comprender cómo minimizar las vulnerabilidades en microservicios que se ejecutan en Kubernetes. Estas actividades están adaptadas para un nivel de comprensión KCSA y asumen que usted tiene acceso `kubectl` a un clúster de Kubernetes.

**Nota:** Cree un namespace de prueba para estos ejercicios si es necesario: `kubectl create namespace microservice-lab`. Recuerde limpiar los recursos después.

## Ejercicio 1: Inspección de Seguridad de Imágenes de Contenedor

**Objetivo:** Comprender aspectos clave de la seguridad de imágenes de contenedor.

**Instrucciones:**

1.  **Escaneo de Vulnerabilidades Conceptual:**
    *   **Discusión:** Herramientas como Trivy, Clair y Grype se utilizan para escanear imágenes de contenedor en busca de vulnerabilidades conocidas (CVEs) en paquetes del SO y dependencias de aplicaciones.
    *   **Actividad (Si tiene una herramienta como Trivy instalada localmente):**
        ```bash
        # Ejemplo: trivy image nginx:latest
        ```
        Si no tiene un escáner, busque en línea "Resultados escaneo Trivy nginx" para ver cómo es una salida típica.
    *   **Observar:** Note los tipos de vulnerabilidades encontradas, su severidad y los paquetes/bibliotecas afectados.
    *   **Nota de Seguridad:** Escanear regularmente las imágenes en su pipeline de CI/CD y en su registro (Seguridad del Repositorio de Imágenes) es crucial para identificar y mitigar vulnerabilidades conocidas antes del despliegue.

**✨ Punto de Predicción ✨**
*Si un escaneo de vulnerabilidades de una imagen oficial `nginx:latest` revela varias CVE de severidad "Alta" en paquetes del SO subyacentes como `libc`, ¿cuáles son tus siguientes pasos inmediatos como desarrollador/operador antes de desplegar esta imagen en producción?*

2.  **Análisis de Dockerfiles para Mejores Prácticas (Ejemplos):**
    *   **Imágenes Base Mínimas - Revise los siguientes fragmentos conceptuales de Dockerfile:**
        *   **Menos Seguro (Base Más Grande):**
            ```dockerfile
            # Dockerfile.menos-seguro
            FROM ubuntu:latest
            RUN apt-get update && apt-get install -y alguna-herramienta python3 dependencias-app
            COPY . /app
            WORKDIR /app
            CMD ["python3", "mi_microservicio.py"]
            ```
        *   **Más Seguro (Base Mínima - Alpine):**
            ```dockerfile
            # Dockerfile.mas-seguro-alpine
            FROM alpine:latest
            RUN apk add --no-cache python3 py3-pip && pip3 install --no-cache-dir -r requirements.txt
            COPY . /app
            WORKDIR /app
            CMD ["python3", "mi_microservicio.py"]
            ```
        *   **Discusión:** Compare la superficie de ataque potencial. La imagen `ubuntu:latest` contiene muchas más utilidades y bibliotecas que `alpine:latest`, aumentando la posibilidad de vulnerabilidades. Las imágenes "Distroless" serían aún más mínimas.
    *   **Builds Multi-Etapa - Revise este ejemplo de Dockerfile:**
        ```dockerfile
        # Dockerfile.multietapa
        # Etapa de Construcción (Build Stage)
        FROM golang:1.19 as builder
        WORKDIR /app
        COPY . .
        RUN CGO_ENABLED=0 GOOS=linux go build -o mi_microservicio .

        # Etapa de Producción (Production Stage)
        FROM alpine:latest
        # FROM gcr.io/distroless/static-debian11 # Base distroless alternativa
        WORKDIR /app
        COPY --from=builder /app/mi_microservicio .
        # COPY --from=builder /app/templates ./templates # Si la app necesita assets estáticos
        # COPY --from=builder /app/static ./static
        USER 1001:1001 # Ejecutar como no-root
        CMD ["./mi_microservicio"]
        ```
        *   **Discusión:** ¿Cómo reduce este build multi-etapa el tamaño final de la imagen y la superficie de ataque? (La imagen final solo contiene el binario compilado y un SO mínimo, no el SDK de Go ni las herramientas de construcción).
    *   **Nota de Seguridad:** Usar imágenes base mínimas y builds multi-etapa son técnicas fundamentales de fortalecimiento de imágenes.

**✅ Punto de Verificación ✅**
*Explica cómo un build multi-etapa, como el ejemplo de `Dockerfile.multietapa`, ayuda específicamente a reducir la superficie de ataque relacionada con herramientas de construcción (por ejemplo, compiladores, SDKs) y dependencias intermedias.*

3.  **Verificación del Registro de Imágenes (Conceptual):**
    *   **Discusión:**
        *   ¿Por qué es importante usar registros privados confiables para las imágenes de su organización? (Control sobre el contenido, control de acceso, integración con escáneres).
        *   ¿Cuáles son los riesgos de obtener imágenes directamente de registros públicos como Docker Hub sin verificación? (Las imágenes podrían ser maliciosas, contener vulnerabilidades críticas o no ser oficiales).
        *   ¿Qué proporciona la "firma de imágenes" (por ejemplo, Notary, Sigstore)? (Aseguramiento de la integridad y procedencia de la imagen).
    *   **Nota de Seguridad:** Su repositorio de imágenes es una parte crítica de su cadena de suministro segura.

**🚀 Tarea de Desafío 🚀**
*Asume que tu organización utiliza un registro de imágenes privado que requiere autenticación. Describe dos medidas de seguridad distintas (una a nivel de registro, una a nivel de pipeline CI/CD) que puedan ayudar a prevenir que una imagen no autorizada o no probada sea desplegada a producción, incluso si un desarrollador la sube accidentalmente al registro.*

## Ejercicio 2: Comunicación Segura Entre Servicios (Network Policies)

**Objetivo:** Usar Network Policies (Políticas de Red) para restringir la comunicación entre Pods de microservicios.

**Instrucciones:**

1.  **Crear un Namespace:**
    ```bash
    kubectl create namespace interservice-sec-lab
    ```

2.  **Desplegar dos Pods de Microservicio (por ejemplo, `frontend` y `backend`):**
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
            image: nginx # Simula frontend
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
          - name: nginx # Simula backend
            image: nginx
            ports:
            - containerPort: 80
        ```
    *   Aplicar ambos:
        ```bash
        kubectl apply -f frontend-pod.yaml -n interservice-sec-lab
        kubectl apply -f backend-pod.yaml -n interservice-sec-lab
        ```
    *   Esperar a los Pods: `kubectl get pods -n interservice-sec-lab -w`
    *   Obtener IP de `backend-svc`: `BACKEND_IP=$(kubectl get pod backend-svc -n interservice-sec-lab -o jsonpath='{.status.podIP}')`

3.  **Verificar Comunicación Inicial (Frontend a Backend):**
    ```bash
    kubectl exec -it frontend-svc -n interservice-sec-lab -- curl --connect-timeout 2 -I $BACKEND_IP
    ```
    *   **Resultado Esperado:** Debería tener éxito (HTTP 200 OK).

**✨ Punto de Predicción ✨**
*Antes de aplicar `backend-netpol.yaml`, si fueras a desplegar un *nuevo* pod (por ejemplo, `pod-atacante`) en el namespace `interservice-sec-lab` (sin ninguna etiqueta específica como `tier: frontend`), ¿sería capaz de comunicarse con `backend-svc` por defecto? ¿Por qué sí o por qué no?*

4.  **Aplicar una Network Policy a `backend-svc` para permitir solo ingreso desde `frontend-svc`:**
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
              tier: backend # Se aplica a backend-svc
          policyTypes:
          - Ingress
          ingress:
          - from:
            - podSelector:
                matchLabels:
                  tier: frontend # Permitir desde frontend-svc
            ports:
            - protocol: TCP
              port: 80
        ```
    *   Aplicar: `kubectl apply -f backend-netpol.yaml -n interservice-sec-lab`

5.  **Verificar Comunicación (Frontend a Backend - debería seguir funcionando):**
    ```bash
    kubectl exec -it frontend-svc -n interservice-sec-lab -- curl --connect-timeout 2 -I $BACKEND_IP
    ```
    *   **Resultado Esperado:** Debería tener éxito.

**✅ Punto de Verificación ✅**
*Después de aplicar `backend-netpol.yaml`, confirma que `frontend-svc` todavía puede alcanzar `backend-svc`. Ahora, si (conceptualmente o realmente) intentas hacer `curl $BACKEND_IP` desde un pod *diferente* en el mismo namespace que *no* tiene la etiqueta `tier: frontend`, ¿cuál es el resultado esperado y por qué la Network Policy impone esto?*

6.  **Intentar Comunicación desde otro Pod (si despliega uno sin la etiqueta `tier: frontend`) o desde un namespace diferente hacia `backend-svc` (Conceptual):**
    *   **Discusión:** Si otro Pod (por ejemplo, `kubectl run test-curl --image=curlimages/curl -n interservice-sec-lab --rm -it -- /bin/sh` y luego `curl $BACKEND_IP`) intenta acceder a `backend-svc`, debería ser bloqueado por la Network Policy.
    *   **Nota de Seguridad:** Las Network Policies son un primer paso crucial para la segmentación de red de microservicios.

**🚀 Tarea de Desafío 🚀**
*Modifica `backend-netpol.yaml` (o crea una nueva política) para lograr lo siguiente: `backend-svc` solo debe aceptar tráfico de ingreso en el puerto TCP 80 desde pods etiquetados como `tier: frontend` Y desde pods dentro de un namespace *diferente* específico, digamos `monitoring-ns`, que tengan la etiqueta `app: prometheus`. Todo otro ingreso debe ser denegado.*

7.  **Limpieza:**
    ```bash
    kubectl delete namespace interservice-sec-lab
    # rm frontend-pod.yaml backend-pod.yaml backend-netpol.yaml (si los guardó)
    ```

## Ejercicio 3: Conceptos de Service Mesh (Conceptual/Análisis)

**Objetivo:** Comprender cómo un Service Mesh (Malla de Servicios) puede mejorar la seguridad de los microservicios.

**Instrucciones (Sin despliegue real - análisis conceptual):**

1.  **Revisar un Manifiesto de Ejemplo de `PeerAuthentication` de Istio (para mTLS):**
    ```yaml
    # Ejemplo de PeerAuthentication de Istio para mTLS
    apiVersion: security.istio.io/v1beta1
    kind: PeerAuthentication
    metadata:
      name: default-mtls
      namespace: su-namespace-de-microservicio # Namespace objetivo
    spec:
      mtls:
        mode: STRICT # Aplica mTLS
    ```
    *   **Discusión:**
        *   ¿Qué implica `mode: STRICT` para los servicios en `su-namespace-de-microservicio`? (Toda la comunicación debe ser mTLS; el tráfico no cifrado es rechazado).
        *   ¿Cómo mejora esto la seguridad sobre las Network Policies únicamente? (Proporciona verificación de identidad y cifrado para el tráfico L7, no solo conectividad L3/L4).

**✨ Punto de Predicción ✨**
*Si un nuevo microservicio `servicio-malicioso` se despliega en `su-namespace-de-microservicio` (donde se aplica el modo `STRICT` de mTLS de Istio) pero su proxy sidecar falla al inyectarse o inicializarse correctamente, ¿qué sucederá cuando `servicio-malicioso` intente comunicarse con otros servicios habilitados para mTLS en el namespace?*

2.  **Revisar un Manifiesto de Ejemplo de `AuthorizationPolicy` de Istio (para AuthZ L7):**
    ```yaml
    # Ejemplo de AuthorizationPolicy de Istio
    apiVersion: security.istio.io/v1beta1
    kind: AuthorizationPolicy
    metadata:
      name: backend-reader-policy
      namespace: su-namespace-de-microservicio
    spec:
      selector:
        matchLabels:
          app: backend-service # La política se aplica a backend-service
      action: ALLOW
      rules:
      - from:
        - source:
            principals: ["cluster.local/ns/su-namespace-de-microservicio/sa/frontend-sa"] # Permitir desde la SA del frontend
        to:
        - operation:
            methods: ["GET"]
            paths: ["/api/data/*"]
    ```
    *   **Discusión:**
        *   ¿Qué permite esta política? (Permite que `frontend-sa` realice solicitudes `GET` a rutas bajo `/api/data/` en `backend-service`).
        *   ¿En qué se diferencia esto de RBAC? (RBAC controla el acceso a los recursos API de Kubernetes; las políticas AuthZ de Service Mesh controlan el acceso entre cargas de trabajo/servicios en la capa de aplicación).
    *   **Nota de Seguridad:** Los Service Meshes proporcionan herramientas poderosas para redes de confianza cero entre microservicios. Comprender sus capacidades es importante para KCSA.

**✅ Punto de Verificación ✅**
*Refiriéndote al ejemplo de `AuthorizationPolicy` de Istio, si `frontend-sa` intenta llamar a `POST /api/data/new-item` en `backend-service`, ¿sería esta solicitud permitida o denegada por esta política específica? Explica tu razonamiento.*

**🚀 Tarea de Desafío 🚀**
*Diseña una `AuthorizationPolicy` de Istio que DENIEGUE explícitamente todo el tráfico no autenticado (es decir, no mTLS) a cualquier servicio en el namespace `su-namespace-de-microservicio`, independientemente de otras políticas de PERMITIR. Esto actúa como una política de respaldo a nivel de namespace. (Pista: Piensa en hacer coincidir solicitudes que *no* tienen un principal de origen).*

## Ejercicio 4: Seguridad de API para Endpoints (Conceptual)

**Objetivo:** Discutir consideraciones de seguridad para los endpoints API de microservicios.

**Instrucciones (Discusión Conceptual):**

1.  **Escenario:** Un microservicio `ServicioPedidos` expone un endpoint `POST /pedidos`.
2.  **Puntos de Discusión:**
    *   **Autenticación:** ¿Cómo se aseguraría de que solo clientes autenticados puedan llamar a este endpoint?
        *   **API Gateway:** El gateway podría validar un JWT o una clave API antes de reenviar la solicitud.
        *   **`ServicioPedidos` mismo:** Si no hay gateway, o para llamadas internas, `ServicioPedidos` podría necesitar validar un JWT pasado en una cabecera `Authorization`.
    *   **Autorización:** Una vez autenticado, ¿cómo decidiría `ServicioPedidos` si el llamante tiene *permiso* para crear un pedido? (por ejemplo, verificar alcances en un JWT, llamar a un servicio de autorización externo, lógica interna basada en ID de usuario).
    *   **Validación de Entradas:** ¿Qué tipo de validación de entradas debería realizar `ServicioPedidos` en el cuerpo de la solicitud para `POST /pedidos`? (Verificar campos requeridos, tipos de datos, longitudes, caracteres maliciosos para prevenir XSS, inyección, etc.).
    *   **Limitación de Tasa (Rate Limiting):** ¿Por qué podría ser importante la limitación de tasa para este endpoint? (Prevenir abuso, DoS).
    *   **Nota de Seguridad:** Cada endpoint de microservicio es un vector de ataque potencial y debe asegurarse con authN, authZ y validación de entradas apropiados.

**✨ Punto de Predicción ✨**
*Para el endpoint `POST /pedidos`, si un API Gateway maneja la validación de JWT para la autenticación, ¿cuál es una responsabilidad de seguridad clave con respecto a ese JWT que *aún* reside típicamente en el `ServicioPedidos` mismo durante la autorización o el procesamiento?*

**✅ Punto de Verificación ✅**
*Imagina que el endpoint `POST /pedidos` espera un payload JSON con `productId` y `quantity`. Proporciona un ejemplo de cómo una validación de entrada insuficiente en `quantity` podría llevar a un problema de seguridad u operacional. ¿Qué tipo de validación se debería aplicar?*

**🚀 Tarea de Desafío 🚀**
*Además de los JWT, nombra otros dos mecanismos o tipos de token comunes que podrían usarse para autenticar clientes (ya sean usuarios u otros servicios) a un endpoint API de microservicio. Para cada uno, describe brevemente un caso de uso típico.*

## Ejercicio 5: Consumo Seguro de Secrets por Microservicios

**Objetivo:** Practicar el montaje y acceso seguro a Secrets en un Pod de microservicio.

**Instrucciones:**

1.  **Crear un Namespace y un Secret:**
    ```bash
    kubectl create namespace app-secrets-lab
    kubectl create secret generic app-api-key --from-literal=api-key='abcdef1234567890' -n app-secrets-lab
    ```

**✨ Punto de Predicción ✨**
*Dado el manifiesto del Pod `microservice-pod-secret.yaml` establece `automountServiceAccountToken: false` y no especifica un `serviceAccountName`, ¿qué identidad usará el Kubelet al intentar obtener el Secret `app-api-key` del API server para montarlo en el pod? ¿Qué permisos RBAC necesitaría esta identidad?*

2.  **Desplegar un Pod (simulando un microservicio) que monte este Secret como un volumen:**
    *   `microservice-pod-secret.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: my-microservice
          namespace: app-secrets-lab
        spec:
          automountServiceAccountToken: false # Buena práctica si no se necesita
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", "echo 'Mi clave API es:'; cat /etc/app-secrets/api-key; echo; sleep 3600"]
            volumeMounts:
            - name: api-key-volume
              mountPath: "/etc/app-secrets"
              readOnly: true
          volumes:
          - name: api-key-volume
            secret:
              secretName: app-api-key
        ```
    *   Aplicar: `kubectl apply -f microservice-pod-secret.yaml -n app-secrets-lab`

3.  **Verificar Acceso y Discutir:**
    *   Verificar registros: `kubectl logs my-microservice -n app-secrets-lab`
    *   **Resultado Esperado:** Los registros deberían mostrar la clave API leída del archivo.
    *   **Discusión:**
        *   ¿Por qué montar como un archivo de solo lectura es generalmente más seguro que como una variable de entorno? (Menos propenso a registro accidental, no heredado tan fácilmente por procesos hijos).
        *   ¿Qué permisos RBAC necesitaría la ServiceAccount usada por este Pod (SA predeterminada, en este caso) relacionados con este Secret para que el Pod se inicie? (El Kubelet, actuando con los privilegios de la SA del Pod, necesita poder hacer `get` al Secret `app-api-key` del API server para montarlo).
    *   **Nota de Seguridad:** Asegúrese de que RBAC controle estrictamente qué ServiceAccounts pueden acceder a Secrets específicos.

**✅ Punto de Verificación ✅**
*Confirma que los registros de `my-microservice` muestran la clave API. Si la ServiceAccount `default` en `app-secrets-lab` *no* tuviera permiso `get` para el Secret `app-api-key`, ¿qué error o comportamiento específico esperarías ver al intentar desplegar el pod, y dónde buscarías información de diagnóstico?*

**🚀 Tarea de Desafío 🚀**
*Modifica (conceptualmente) el `microservice-pod-secret.yaml` para consumir la `api-key` del Secret como una variable de entorno en lugar de un archivo montado. ¿Cuáles son los cambios específicos necesarios en el manifiesto? ¿Cuál es un riesgo de seguridad adicional introducido al usar variables de entorno para secretos en comparación con montajes de archivos en este contexto?*

4.  **Limpieza:**
    ```bash
    kubectl delete namespace app-secrets-lab
    # rm microservice-pod-secret.yaml (si lo guardó)
    ```

## Ejercicio 6: Observabilidad para la Seguridad (Enfoque en Logging)

**Objetivo:** Comprender el rol del logging (registro) en la seguridad de microservicios.

**Instrucciones:**

1.  **Desplegar un Pod Simple que Escriba en Stdout:**
    *   `logging-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: logging-app
          namespace: default # O su namespace de prueba
        spec:
          containers:
          - name: app
            image: busybox
            command: ["sh", "-c", "i=0; while true; do echo \"Entrada de log $i: Usuario 'usuarioPrueba' intentó acción X en $(date)\"; i=$((i+1)); sleep 5; done"]
        ```
    *   Aplicar: `kubectl apply -f logging-pod.yaml`

2.  **Ver Registros:**
    ```bash
    kubectl logs -f logging-app
    ```
    (Ctrl+C para detener)

**✨ Punto de Predicción ✨**
*El Pod `logging-app` registra "Usuario 'usuarioPrueba' intentó acción X". Si esto fuera una aplicación real, ¿cuáles son dos piezas críticas de información contextual que faltan en este mensaje de registro que serían esenciales para una investigación efectiva de incidentes de seguridad?*

3.  **Discusión:**
    *   **¿Qué tipo de información relevante para la seguridad *debería* registrar un microservicio?**
        *   Intentos de autenticación (éxito/fracaso, IP de origen, nombre de usuario si aplica).
        *   Decisiones de autorización (concedida/denegada, para qué recurso/acción).
        *   Operaciones significativas o cambios de estado iniciados por usuarios/sistemas.
        *   Errores críticos o excepciones que podrían indicar compromiso o mal funcionamiento.
        *   Detalles de la solicitud API (endpoint, origen, user-agent, pero con cuidado con PII).
    *   **¿Qué información sensible *nunca* debería registrar un microservicio?**
        *   Contraseñas en bruto, claves API, tokens de sesión, números completos de tarjetas de crédito.
        *   PII detallada a menos que sea absolutamente necesario y esté debidamente protegida/enmascarada.
        *   Claves de cifrado.
    *   **¿Cómo ayudaría el logging centralizado (por ejemplo, pila ELK, Splunk, soluciones del proveedor de la nube) a correlacionar eventos de seguridad de múltiples microservicios?** (Proporciona un único lugar para buscar, analizar y alertar sobre registros de todos los servicios, facilitando el rastreo de una cadena de ataque o la identificación de problemas generalizados).
    *   **Nota de Seguridad:** Un logging adecuado es esencial para la detección, respuesta y análisis forense. Sin embargo, los propios registros pueden convertirse en un objetivo si contienen datos sensibles o no están adecuadamente protegidos.

**✅ Punto de Verificación ✅**
*Explica por qué registrar claves API en bruto o tokens de sesión es un riesgo de seguridad grave. Si un sistema de agregación de registros se ve comprometido, ¿cuál es el impacto potencial si dichos datos sensibles están presentes en los registros?*

**🚀 Tarea de Desafío 🚀**
*Describe un escenario donde tener *muy pocos* registros (o la falta de campos de registro cruciales) para un microservicio de autenticación podría dificultar la capacidad de detectar o responder a un ataque de fuerza bruta de contraseñas. ¿Qué campos de registro específicos serían vitales en este escenario?*

4.  **Limpieza:**
    ```bash
    kubectl delete pod logging-app
    # rm logging-pod.yaml (si lo guardó)
    # kubectl delete namespace microservice-lab (si lo creó y ha terminado)
    ```

Esta guía de laboratorio proporciona un punto de partida. Experimente más con estos conceptos en su clúster.

