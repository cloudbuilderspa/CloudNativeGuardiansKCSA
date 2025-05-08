# Temas Clave: Monitorización, Registro (Logging) y Seguridad en Tiempo de Ejecución

Esta sección profundiza en configuraciones avanzadas, técnicas específicas y herramientas para una monitorización, registro y seguridad en tiempo de ejecución efectivos en Kubernetes. Estos temas clave se basan en los conceptos principales y son esenciales para una comprensión a nivel KCSA sobre cómo mantener una postura de seguridad proactiva y receptiva.

## Configuración Avanzada de Políticas de Auditoría de Kubernetes

Los registros de auditoría de Kubernetes son una rica fuente de información de seguridad. Una política de auditoría bien configurada es crucial para capturar eventos relevantes sin sobrecargar las capacidades de almacenamiento o análisis.

*   **Profundización en la Estructura de la Política de Auditoría:**
    *   **Reglas (Rules):** Un archivo de política de auditoría consiste en una lista de reglas. Cada solicitud al API server se evalúa contra estas reglas en orden. La primera regla que coincida determina el nivel de auditoría para esa solicitud.
    *   **Niveles (Levels):**
        *   `None`: No registrar eventos que coincidan con esta regla.
        *   `Metadata`: Registrar metadatos de la solicitud (usuario solicitante, marca de tiempo, recurso, verbo, etc.) pero no el cuerpo de la solicitud o respuesta.
        *   `Request`: Registrar metadatos del evento y cuerpo de la solicitud pero no el cuerpo de la respuesta. Útil para todas las solicitudes mutantes.
        *   `RequestResponse`: Registrar metadatos del evento, cuerpo de la solicitud y cuerpo de la respuesta. Usar con moderación ya que los cuerpos de respuesta pueden ser grandes, especialmente para solicitudes `get` o `list` sobre recursos grandes.
    *   **Etapas (Stages):** Definen en qué etapa de la ejecución se debe auditar un evento.
        *   `RequestReceived`: Se genera tan pronto como el API server recibe la solicitud, antes de que sea procesada por la cadena de admisión.
        *   `ResponseStarted`: Se envía una vez que se envían las cabeceras de respuesta, pero antes de que se envíe el cuerpo de la respuesta.
        *   `ResponseComplete`: Se envía cuando el cuerpo de la respuesta se ha enviado completamente y la conexión se cierra. Esta es la etapa más común para registrar.
        *   `Panic`: Se genera cuando ocurre un pánico (panic).
*   **Ejemplos de Reglas para Objetivos Específicos de Monitorización de Seguridad:**
    *   **Rastrear todos los comandos `exec`:**
        ```yaml
        - level: RequestResponse
          resources:
          - group: "" # grupo API principal (core)
            resources: ["pods/exec"]
        ```
    *   **Rastrear todo el acceso a Secrets (lecturas):**
        ```yaml
        - level: Request # O RequestResponse si necesita ver el contenido del secret (usar con precaución)
          resources:
          - group: ""
            resources: ["secrets"]
          verbs: ["get", "list", "watch"]
        ```
    *   **Rastrear todos los cambios de RBAC:**
        ```yaml
        - level: RequestResponse
          resources:
          - group: "rbac.authorization.k8s.io"
            resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
        ```
*   **Omisión de Eventos Ruidosos pero de Bajo Riesgo:**
    *   Es común omitir solicitudes de lectura frecuentes y de bajo impacto, como actualizaciones de estado de Kubelets o verificaciones de salud (health checks).
        ```yaml
        - level: None
          users: ["system:kubelet"] # Ejemplo: omitir lecturas del Kubelet para su propio nodo
          verbs: ["get", "watch"]
          resources:
          - group: ""
            resources: ["nodes"] # Ser específico
        - level: None
          userGroups: ["system:nodes"]
          verbs: ["get"]
          resources:
          - group: ""
            resources: ["pods"] # El Kubelet necesita obtener pods en su nodo
        ```
*   **Relevancia para KCSA:** Comprender la estructura de un archivo de política de auditoría y cómo definir reglas para capturar eventos de seguridad críticos mientras se gestiona el volumen de registros.

## Integración de Registros y Métricas con Plataformas SIEM/Observabilidad

Centralizar los registros y métricas es clave para un análisis y correlación efectivos.

*   **Visión General Conceptual:**
    *   **Reenvío de Registros (Log Forwarding):** Agentes (como Fluentd, Fluent Bit, Vector) se despliegan en los nodos (a menudo como DaemonSets) para recolectar registros de diversas fuentes:
        *   Registros de contenedores (stdout/stderr, típicamente de `/var/log/pods/` o `/var/log/containers/`).
        *   Registros del sistema del nodo (`/var/log/messages`, `journald`).
        *   Registros de Auditoría de Kubernetes (desde la ruta de archivo especificada en la configuración del API server).
        *   Archivos de registro específicos de la aplicación.
    *   Estos agentes luego reenvían los registros a un backend de registro centralizado o sistema SIEM (Gestión de Información y Eventos de Seguridad) como Elasticsearch (Pila ELK), Splunk, Sumo Logic, etc.
    *   **Recolección de Métricas (Metrics Scraping):** Prometheus se usa comúnmente para recolectar métricas de:
        *   Componentes de Kubernetes (API Server, Kubelet, Controller Manager, Scheduler, etcd).
        *   Node Exporter (para métricas del SO a nivel de nodo).
        *   Aplicaciones que exponen métricas en un formato compatible con Prometheus.
    *   Las métricas se almacenan en la base de datos de series temporales de Prometheus y pueden visualizarse con Grafana o alimentarse a sistemas de alerta.
*   **Beneficios para la Seguridad:**
    *   **Correlación:** Capacidad para correlacionar eventos de diferentes fuentes (por ejemplo, un evento de auditoría de API con una entrada de registro de aplicación específica y una actividad de proceso a nivel de nodo).
    *   **Consultas y Análisis Avanzados:** Los SIEMs proporcionan potentes lenguajes de consulta y herramientas analíticas para buscar en grandes volúmenes de datos de registro.
    *   **Alertas:** Configurar alertas en el SIEM o sistema de monitorización para eventos de seguridad específicos o patrones anómalos.
    *   **Almacenamiento a Largo Plazo y Cumplimiento:** Los sistemas centralizados pueden manejar los requisitos de almacenamiento a largo plazo y retención para el cumplimiento.
*   **Relevancia para KCSA:** Comprender la importancia de la centralización para registros y métricas y ser consciente de los patrones arquitectónicos comunes (por ejemplo, reenviadores de registros, Prometheus para métricas).

## Estrategias de Detección de Anomalías en Tiempo de Ejecución

Identificar desviaciones del comportamiento normal puede indicar un incidente de seguridad.

*   **Más Allá de la Detección Basada en Reglas:**
    *   Si bien la detección basada en reglas (por ejemplo, reglas de Falco como "shell ejecutado en contenedor") es efectiva para comportamientos maliciosos conocidos, la detección de anomalías tiene como objetivo identificar amenazas *desconocidas* aprendiendo una línea base de actividad normal y señalando las desviaciones.
*   **Técnicas (Conceptual para KCSA):**
    *   **Monitorización de Actividad de Procesos:** Establecer una línea base de los procesos normales que se ejecutan en un contenedor y alertar sobre ejecuciones de procesos nuevas o inesperadas.
    *   **Perfilado de Conexiones de Red:** Aprender las conexiones de red entrantes/salientes típicas para un Pod/servicio y alertar sobre conexiones nuevas o inusuales (por ejemplo, a una IP maliciosa conocida, puertos inesperados).
    *   **Análisis de Patrones de Syscall:** Monitorizar secuencias o frecuencias de llamadas al sistema realizadas por procesos e identificar desviaciones de una línea base aprendida. Esto puede ser indicativo de explotación o malware.
    *   **Análisis de Comportamiento de Usuario/Entidad (UEBA):** Para la actividad del API server o del usuario, establecer una línea base de las acciones típicas del usuario y detectar comportamientos anómalos (por ejemplo, un usuario que accede repentinamente a recursos inusuales o realiza acciones en horarios extraños).
*   **Desafíos:** La detección de anomalías puede ser propensa a falsos positivos si la línea base no está bien establecida o si el comportamiento legítimo cambia con frecuencia. A menudo requiere un período de aprendizaje.
*   **Relevancia para KCSA:** Comprender el concepto de detección de anomalías como un enfoque complementario a la detección basada en reglas para la seguridad en tiempo de ejecución.

## El Rol de eBPF en la Seguridad en Tiempo de Ejecución (Conceptual)

eBPF (extended Berkeley Packet Filter) es una potente tecnología del kernel que está revolucionando la observabilidad y la seguridad.

*   **Breve Explicación de eBPF:**
    *   eBPF permite que programas en modo sandbox se ejecuten directamente en el kernel de Linux sin cambiar el código fuente del kernel ni cargar módulos del kernel.
    *   Estos programas eBPF pueden adjuntarse a varios puntos de enganche (hooks) del kernel (por ejemplo, llamadas al sistema, eventos de red, kprobes) para recolectar datos o aplicar políticas con una sobrecarga muy baja.
*   **Cómo eBPF Habilita las Herramientas de Seguridad en Tiempo de Ejecución:**
    *   **Visibilidad Profunda:** eBPF proporciona visibilidad granular de las actividades a nivel de kernel como llamadas al sistema, paquetes de red y ejecución de procesos, lo cual es invaluable para la monitorización de seguridad.
    *   **Baja Sobrecarga:** En comparación con métodos más antiguos como los módulos del kernel o ptrace, eBPF es generalmente más eficiente y seguro.
    *   **Aplicación de Seguridad:** eBPF también se puede utilizar para aplicar políticas de seguridad a nivel del kernel (por ejemplo, bloquear ciertas llamadas al sistema, descartar paquetes de red).
    *   **Herramientas que Aprovechan eBPF:** Muchas herramientas modernas de seguridad nativas de la nube utilizan eBPF, incluyendo:
        *   **Cilium:** Para redes y seguridad de red (usa eBPF para enrutamiento, NetworkPolicies, balanceo de carga).
        *   **Falco:** Puede usar un controlador eBPF como alternativa a su módulo de kernel para recolectar eventos de syscall.
        *   **Tracee, Pixie:** Para observabilidad y seguridad en tiempo de ejecución.
*   **Relevancia para KCSA:** Tener una conciencia de alto nivel de qué es eBPF y por qué es una tecnología habilitadora importante para las herramientas modernas de seguridad en tiempo de ejecución y observabilidad en entornos nativos de la nube.

## Técnicas de Respuesta a Incidentes Específicas de Contenedores

Responder a incidentes en un entorno contenerizado tiene aspectos únicos.

*   **Aislamiento de un Pod/Nodo Comprometido:**
    *   **Network Policies:** Aplicar o actualizar inmediatamente Network Policies para restringir todo el tráfico de entrada y salida del Pod o Pods comprometidos que coincidan con sus etiquetas.
    *   **`kubectl cordon <nombre-del-nodo>`:** Marca el nodo como no programable, evitando que se coloquen nuevos Pods en él. Los Pods existentes continúan ejecutándose.
    *   **`kubectl drain <nombre-del-nodo> --ignore-daemonsets --delete-emptydir-data`:** Desaloja Pods del nodo de forma segura (respetando PDBs) antes del mantenimiento o la retirada. Usar con precaución durante un incidente si necesita datos forenses de los Pods.
    *   **Eliminación/Reducción de Escala de Pods:** Si la eliminación inmediata de la amenaza es primordial y el análisis forense es secundario o se puede hacer desde instantáneas, eliminar el Pod o reducir la escala de su controlador (Deployment, StatefulSet) a cero puede detener la actividad maliciosa.
*   **Recolección de Evidencia Forense de Contenedores:**
    *   **`kubectl logs <nombre-del-pod> [-c <nombre-del-contenedor>]`:** Recolectar registros del contenedor.
    *   **`kubectl exec <nombre-del-pod> [-c <nombre-del-contenedor>] -- <comando>`:** Si es seguro y el contenedor aún se está ejecutando, ejecutar `exec` para realizar comandos de investigación (por ejemplo, `ps`, `ls`, `netstat`). Tenga cuidado ya que esto puede alterar el estado.
    *   **`kubectl cp <namespace>/<nombre-del-pod>:<ruta/al/archivo/en/contenedor> <ruta/local>`:** Copiar archivos fuera de un contenedor.
    *   **Herramientas de Snapshotting/Checkpointing de Contenedores:** Algunos entornos de ejecución de contenedores o herramientas especializadas (por ejemplo, CRIU con Docker/Podman, `kubectl-capture`) podrían permitir realizar un checkpoint del estado de un contenedor en ejecución en disco para su análisis posterior. Esto es más avanzado.
*   **Importancia de la Naturaleza Efímera:**
    *   La evidencia puede perderse rápidamente si un Pod comprometido falla, es desalojado o su nodo es terminado por un autoescalador.
    *   Tener un registro y una monitorización centralizados robustos es crítico porque la fuente de evidencia podría desaparecer.
*   **Relevancia para KCSA:** Comprender los comandos básicos de Kubernetes para la contención y ser consciente de los métodos para la recolección de evidencia de contenedores, reconociendo los desafíos que plantea su naturaleza efímera.

## Adherencia a Benchmarks y Guías de Fortalecimiento para Configuraciones en Tiempo de Ejecución

Asegurar que las configuraciones en tiempo de ejecución se alineen con las mejores prácticas de seguridad.

*   **CIS Benchmarks para Kubernetes:**
    *   El Center for Internet Security (CIS) publica benchmarks ampliamente respetados para Kubernetes, proporcionando orientación prescriptiva para el fortalecimiento de varios componentes.
    *   Estos benchmarks cubren configuraciones en tiempo de ejecución para:
        *   Componentes del Plano de Control (API Server, Controller Manager, Scheduler, Etcd).
        *   Componentes del Nodo Trabajador (Kubelet, Entorno de Ejecución de Contenedores).
        *   Network Policies, Pod Security Policies (obsoletas pero los principios se aplican a PSA).
*   **Importancia de la Revisión Regular:**
    *   Las configuraciones pueden desviarse con el tiempo debido a cambios manuales o actualizaciones.
    *   Auditar regularmente las configuraciones de su clúster contra los CIS Benchmarks relevantes (u otras guías de fortalecimiento como las de la NSA/CISA).
    *   Herramientas como `kube-bench` pueden automatizar la verificación del cumplimiento con los CIS Benchmarks.
*   **Relevancia para KCSA:** Ser consciente de la existencia e importancia de los CIS Benchmarks como fuente de mejores prácticas para la configuración segura de Kubernetes, incluyendo aspectos del tiempo de ejecución.

Al dominar estos temas clave, las personas pueden mejorar significativamente su capacidad para monitorizar, registrar eficazmente y asegurar las cargas de trabajo de Kubernetes en tiempo de ejecución, formando una parte crítica de un conjunto de habilidades KCSA completo.

