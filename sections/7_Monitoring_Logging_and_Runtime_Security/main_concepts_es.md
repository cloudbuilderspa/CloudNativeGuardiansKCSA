# Conceptos Principales: Monitorización, Registro (Logging) y Seguridad en Tiempo de Ejecución

La seguridad efectiva no termina en el despliegue. La monitorización continua, un registro (logging) exhaustivo y medidas robustas de seguridad en tiempo de ejecución son esenciales para detectar, responder y mitigar amenazas en un entorno Kubernetes en vivo. Esta sección cubre estos aspectos críticos de seguridad operacional, relevantes para la certificación KCSA, basándose en dominios como "Seguridad de Plataforma (Observabilidad)" y "Visión General de la Seguridad Cloud Native".

## Introducción a la Seguridad en Tiempo de Ejecución (Runtime Security)

*   **¿Qué es la Seguridad en Tiempo de Ejecución?**
    La seguridad en tiempo de ejecución se refiere a la protección de aplicaciones e infraestructura *mientras están en funcionamiento*. Se enfoca en detectar y responder a amenazas activas, comportamiento malicioso y violaciones de políticas dentro de las cargas de trabajo activas y el propio clúster.

*   **Diferencia entre Seguridad Pre-Despliegue y Seguridad en Tiempo de Ejecución:**
    *   **Seguridad Pre-Despliegue (Shift-Left):** Se enfoca en prevenir vulnerabilidades *antes* del despliegue. Esto incluye codificación segura, escaneo de imágenes, configuración segura de manifiestos y seguridad de IaC (Infraestructura como Código).
    *   **Seguridad en Tiempo de Ejecución:** Asume que no todas las vulnerabilidades pueden detectarse antes del despliegue y que pueden surgir nuevas amenazas. Se trata de identificar y mitigar amenazas que se manifiestan en el entorno en ejecución.
    *   Ambas son componentes cruciales de una estrategia de defensa en profundidad.

## Monitorización Continua para la Detección de Amenazas

*   **Importancia:** Monitorizar activamente el clúster y sus cargas de trabajo es vital para la detección temprana de amenazas. Los atacantes pueden intentar explotar vulnerabilidades, escalar privilegios, moverse lateralmente o exfiltrar datos. La monitorización continua ayuda a identificar estas acciones.
*   **Áreas Clave a Monitorizar:**
    *   **Comportamiento de Pods:** Ejecución inesperada de procesos dentro de contenedores, conexiones de red anómalas desde/hacia Pods, modificaciones del sistema de archivos, anomalías en llamadas al sistema (syscalls).
    *   **Tráfico de Red:** Patrones de tráfico inusuales entre Pods, hacia/desde redes externas, escaneo de puertos, consultas DNS inesperadas.
    *   **Acceso al API Server:** Solicitudes API no autorizadas o sospechosas (monitorizadas mediante Registros de Auditoría), fallos de autenticación, cambios en RBAC.
    *   **Actividad de Nodos:** Procesos inusuales en nodos, acceso no autorizado a recursos del nodo, actividad del Kubelet.
    *   **Actividad del Entorno de Ejecución de Contenedores (Container Runtime):** Creación/eliminación de contenedores, errores del entorno de ejecución que podrían indicar un compromiso.

## Logging (Registro) para Seguridad (Enfoque en Tiempo de Ejecución)

Un registro exhaustivo es la base para la observabilidad y la respuesta a incidentes.

*   **Registros de Aplicación:**
    *   **Qué Registrar:** Las aplicaciones que se ejecutan en Pods deben generar registros para eventos relevantes para la seguridad: intentos de autenticación (éxito/fracaso), decisiones de autorización, operaciones significativas de lógica de negocio, errores y fallos de validación de entradas.
    *   **Mejores Prácticas:** Usar registro estructurado (por ejemplo, JSON) para facilitar el análisis y la interpretación. Evitar registrar datos sensibles (contraseñas, PII, tokens) en texto plano.
*   **Registros de Auditoría de Kubernetes (Kubernetes Audit Logs):**
    *   **(Recapitulación de Importancia):** Como se cubrió en Fortalecimiento del Clúster, los registros de auditoría proporcionan un registro detallado de todas las solicitudes al API Server. Son cruciales para rastrear quién hizo qué, cuándo y a qué recursos.
    *   **Relevancia en Tiempo de Ejecución:** Analizar los registros de auditoría en tiempo real o casi real puede ayudar a detectar ataques en curso o violaciones de políticas (por ejemplo, acceso no autorizado a Secrets, manipulación de RBAC).
*   **Registros de Nodo:**
    *   **Registros a Nivel de SO:** Registros del sistema operativo subyacente en nodos trabajadores y del plano de control (por ejemplo, `syslog`, `journald`, `auth.log`). Estos pueden revelar intentos de inicio de sesión no autorizados en nodos, explotaciones a nivel de kernel o actividad de malware.
    *   **Registros del Entorno de Ejecución de Contenedores:** Los registros del entorno de ejecución de contenedores (Docker, containerd, CRI-O) pueden mostrar errores o eventos relacionados con la gestión del ciclo de vida del contenedor que podrían ser relevantes para la seguridad.
*   **Centralización y Análisis:**
    *   **Importancia:** Verificar manualmente los registros en Pods o nodos individuales no es práctico. Los registros de todas las fuentes (aplicaciones, API Server, nodos, entornos de ejecución) deben enviarse a una plataforma de registro centralizada (por ejemplo, Elasticsearch/Logstash/Kibana - ELK, Splunk, servicios de registro de proveedores de nube).
    *   **Beneficios:** Permite la correlación de eventos entre diferentes componentes, búsqueda más fácil, almacenamiento a largo plazo y alertas automatizadas basadas en patrones de registro.

## Métricas de Seguridad

Las métricas proporcionan información cuantitativa sobre la postura de seguridad y pueden usarse para alertas.

*   **Indicadores Clave de Rendimiento (KPIs) para la Seguridad en Tiempo de Ejecución:**
    *   Número de violaciones de Pod Security Admission (PSA) (audit/warn/enforce).
    *   Tasa de fallos de autenticación del API Server.
    *   Número de denegaciones de autorización RBAC.
    *   Conteos o volúmenes anómalos de conexiones de red por Pod/Servicio.
    *   Número de alertas de herramientas de seguridad en tiempo de ejecución (por ejemplo, Falco).
    *   Alertas de agotamiento de recursos (CPU, memoria, disco) que podrían indicar un DoS o un proceso descontrolado.
    *   Número de vulnerabilidades críticas detectadas en imágenes en ejecución (si se realiza escaneo continuo).
*   **Herramientas de Monitorización (Conceptual):**
    *   Herramientas como Prometheus pueden recolectar métricas de componentes de Kubernetes (API Server, Kubelet, etcd) y aplicaciones.
    *   Grafana puede usarse para visualizar estas métricas en dashboards, facilitando la detección de tendencias y anomalías.
    *   Alertmanager (parte del ecosistema Prometheus) puede activar alertas basadas en umbrales predefinidos para métricas de seguridad.
*   **Relevancia para KCSA:** Comprender que recolectar y analizar métricas relacionadas con la seguridad es parte de mantener la conciencia de la seguridad operacional.

## Sistemas de Detección y Prevención de Intrusiones (IDS/IPS) en el Contexto de Kubernetes

*   **IDS (Sistema de Detección de Intrusiones):** Monitoriza actividades de red y/o sistema en busca de actividades maliciosas o violaciones de políticas y las reporta.
*   **IPS (Sistema de Prevención de Intrusiones):** Monitoriza como un IDS pero también puede bloquear o prevenir activamente las intrusiones detectadas.
*   **Aplicación en Kubernetes:**
    *   **IDS/IPS de Red (NIDS/NIPS):** Pueden desplegarse en los puntos de entrada/salida del clúster o dentro de la red del clúster (por ejemplo, como parte de un plugin CNI o service mesh) para monitorizar el tráfico este-oeste en busca de firmas de ataques conocidos o comportamiento anómalo.
    *   **IDS/IPS Basado en Host (HIDS/HIPS):** Desplegado en nodos individuales para monitorizar la actividad a nivel de nodo, llamadas al sistema (syscalls) e integridad del sistema de archivos. Las herramientas de seguridad en tiempo de ejecución a menudo actúan como HIDS.
    *   **Herramientas de Seguridad en Tiempo de Ejecución como IDS:** Herramientas como Falco funcionan principalmente como un IDS, detectando violaciones de políticas o comportamiento sospechoso en tiempo de ejecución y generando alertas. Algunos sistemas avanzados podrían ofrecer capacidades limitadas de IPS.
*   **Relevancia para KCSA:** Comprender la diferencia básica entre IDS e IPS y cómo sus principios se aplican para detectar y responder a amenazas en un entorno Kubernetes.

## Herramientas Comunes de Seguridad en Tiempo de Ejecución (Visión General Conceptual)

*   **Falco:**
    *   Un proyecto de seguridad en tiempo de ejecución nativo de la nube y de código abierto, ahora un proyecto incubado por la CNCF.
    *   Detecta comportamiento inesperado de aplicaciones y alerta sobre amenazas en tiempo de ejecución.
    *   Utiliza llamadas al sistema (syscalls) como fuente de datos principal a través de módulos del kernel o sondas eBPF. También puede consumir registros de auditoría de Kubernetes y otras fuentes de eventos.
    *   Usa un motor basado en reglas para definir y detectar actividades sospechosas (por ejemplo, ejecución de un shell en un contenedor, conexión de red inesperada, acceso a archivos sensibles).
*   **Sysdig Secure:**
    *   Una oferta comercial construida sobre las tecnologías de código abierto Falco y Sysdig.
    *   Proporciona capacidades más amplias de seguridad en tiempo de ejecución, incluyendo gestión de vulnerabilidades, cumplimiento, detección de amenazas y análisis forense. A menudo incluye características más avanzadas, una interfaz de usuario y soporte empresarial.
*   **Otras Categorías:**
    *   **Herramientas basadas en eBPF:** Un número creciente de herramientas aprovecha eBPF (extended Berkeley Packet Filter) para una observabilidad profunda a nivel de kernel y aplicación de la seguridad con menor sobrecarga (por ejemplo, Cilium, Tracee).
    *   **Herramientas de Análisis Forense de Contenedores:** Herramientas diseñadas para capturar y analizar el estado de un contenedor después de un incidente de seguridad.
*   **Conocimiento a Nivel KCSA:** Ser consciente de la existencia y el propósito de estas categorías de herramientas, especialmente Falco como un ejemplo prominente de código abierto. No se espera un conocimiento operativo profundo, pero comprender su rol en la seguridad en tiempo de ejecución es importante.

## Respuesta Básica a Incidentes en Kubernetes

Una comprensión de alto nivel sobre cómo reaccionar cuando se activa una alerta de seguridad en tiempo de ejecución.
*   **Cuando se Activa una Alerta:**
    1.  **Triaje (Triage):** Validar la alerta. ¿Es un verdadero positivo o un falso positivo?
    2.  **Contención (Containment):** Si es un verdadero positivo, el objetivo inmediato es contener la amenaza y prevenir más daños o movimiento lateral.
        *   **Aislar Pods/Nodos Afectados:**
            *   Aplicar Network Policies restrictivas al(los) Pod(s) afectado(s).
            *   Acordonar el nodo (`kubectl cordon <nombre-del-nodo>`) para evitar que se programen nuevos Pods allí.
            *   Potencialmente drenar el nodo (`kubectl drain <nombre-del-nodo> --ignore-daemonsets`) después de mover las cargas de trabajo si es seguro.
            *   Eliminar el(los) Pod(s) comprometido(s) si es necesario, pero considerar primero el análisis forense.
    3.  **Recolección de Evidencia (Análisis Forense):**
        *   Recolectar registros del Pod afectado, aplicación, nodo y registros de auditoría del API Server.
        *   Tomar una instantánea (snapshot) del sistema de archivos del Pod o del estado del contenedor si es posible (avanzado).
        *   Registrar el tráfico de red si hay herramientas implementadas.
    4.  **Erradicación y Remediación:**
        *   Identificar la causa raíz del incidente (por ejemplo, vulnerabilidad explotada, credencial robada).
        *   Parchear vulnerabilidades, actualizar configuraciones, revocar credenciales comprometidas.
    5.  **Recuperación:**
        *   Restaurar los servicios afectados desde un estado bueno conocido (por ejemplo, redesplegar desde una imagen limpia, restaurar datos desde una copia de seguridad).
    6.  **Lecciones Aprendidas:** Realizar una revisión post-incidente para mejorar las medidas de seguridad y los procedimientos de respuesta.
*   **Relevancia para KCSA:** Comprender las fases básicas de la respuesta a incidentes y cómo las características de Kubernetes (Network Policies, acordonamiento) pueden ayudar en la contención.

## Asegurando la Integridad de la Carga de Trabajo en Tiempo de Ejecución

Verificar que las cargas de trabajo en ejecución no hayan sido manipuladas.
*   **Monitorización de Integridad de Archivos (FIM - File Integrity Monitoring):**
    *   **Concepto:** Herramientas que monitorizan archivos críticos del sistema operativo y de aplicaciones en busca de cambios no autorizados.
    *   **Aplicación en Kubernetes:** Puede usarse en nodos trabajadores para proteger archivos del Kubelet, archivos del entorno de ejecución de contenedores o archivos críticos del SO. También puede usarse dentro de contenedores (aunque menos común debido al principio de inmutabilidad) para casos de uso específicos.
*   **Detección de Ejecución Inesperada de Procesos o Conexiones de Red:**
    *   Las herramientas de seguridad en tiempo de ejecución (como Falco) destacan en esto al monitorizar llamadas al sistema.
    *   Se pueden generar alertas si un contenedor inicia un proceso inesperado (por ejemplo, un shell, un escáner de red) o realiza una conexión saliente a una dirección IP desconocida.
*   **Relevancia para KCSA:** Apreciar que la seguridad en tiempo de ejecución incluye verificar la integridad de las cargas de trabajo y detectar desviaciones del comportamiento esperado.

La monitorización, el registro y la seguridad en tiempo de ejecución efectivos forman un bucle de retroalimentación crítico, permitiendo a las organizaciones detectar amenazas que eluden los controles preventivos y responder rápidamente para proteger sus clústeres y aplicaciones de Kubernetes.

