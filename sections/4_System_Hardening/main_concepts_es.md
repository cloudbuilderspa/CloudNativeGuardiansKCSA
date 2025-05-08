# Conceptos Principales: El Modelo de Amenaza de Kubernetes

Comprender el modelo de amenaza de Kubernetes es esencial para un fortalecimiento (hardening) efectivo del sistema y la seguridad general. El modelado de amenazas es un proceso proactivo de identificación de amenazas potenciales, vulnerabilidades y vectores de ataque relevantes para un sistema, y luego la definición de contramedidas para prevenir o mitigar su impacto. Esta sección, basada en el dominio "Modelo de Amenaza de Kubernetes (16%)" de KCSA, explora estos conceptos.

## Introducción al Modelado de Amenazas de Kubernetes

**¿Qué es el Modelado de Amenazas?**
El modelado de amenazas en el contexto de Kubernetes implica:
1.  Identificar activos valiosos dentro del clúster (por ejemplo, datos sensibles, componentes del plano de control, cargas de trabajo de aplicaciones).
2.  Definir límites de confianza (ver más abajo).
3.  Identificar amenazas y atacantes potenciales (por ejemplo, usuario interno malicioso, atacante externo, carga de trabajo comprometida).
4.  Analizar vectores de ataque y vulnerabilidades potenciales para cada componente y flujo de datos.
5.  Priorizar amenazas y definir estrategias de mitigación.

Frameworks como STRIDE (Suplantación de Identidad, Manipulación de Datos, Repudio, Divulgación de Información, Denegación de Servicio, Elevación de Privilegios) pueden usarse para categorizar amenazas.

**¿Por qué es Importante para Kubernetes?**
Kubernetes es un sistema distribuido complejo con muchos componentes e interacciones. Esta complejidad crea una gran superficie de ataque. El modelado de amenazas ayuda a:
*   Identificar sistemáticamente las debilidades de seguridad.
*   Priorizar los esfuerzos e inversiones en seguridad.
*   Diseñar configuraciones de clúster y despliegues de aplicaciones más seguros.
*   Mejorar la preparación para la respuesta a incidentes.

## Límites de Confianza y Flujo de Datos de Kubernetes

Comprender dónde se encuentran los límites de confianza y cómo fluyen los datos es fundamental para identificar amenazas potenciales.

### Límites de Confianza Clave

Un límite de confianza es una línea donde cambia el nivel de confianza. Cruzar un límite de confianza típicamente requiere alguna forma de autenticación o autorización.
*   **Plano de Control vs. Plano de Datos:** El plano de control (API Server, etcd, Controller Manager, Scheduler) es altamente confiable. El plano de datos (nodos trabajadores, Kubelets, Pods) es generalmente menos confiable. La comunicación desde el plano de datos al plano de control (por ejemplo, Kubelet al API Server) es un límite de confianza crítico.
*   **Aislamiento de Nodos:** Cada nodo trabajador debe estar aislado de los demás para evitar que un compromiso en un nodo se propague fácilmente. El Kubelet en un nodo es un componente privilegiado.
*   **Pod-a-Pod:** Por defecto, los Pods en la misma red del clúster pueden comunicarse. Las Network Policies (Políticas de Red) crean límites de confianza entre Pods/namespaces.
*   **Contenedor-a-Contenedor (dentro de un Pod):** Los contenedores en el mismo Pod comparten la red y a menudo otros namespaces, lo que representa un límite de confianza muy débil.
*   **Pod-a-Nodo (Escape de Contenedor):** Un límite crítico. Si un proceso de contenedor escapa al nodo subyacente, puede comprometer potencialmente todo el nodo y otros Pods en él.
*   **Mundo Externo al Clúster:** Cualquier interacción desde fuera del clúster (por ejemplo, un usuario con `kubectl`, tráfico de ingreso) cruza un importante límite de confianza.

### Flujos de Datos Críticos e Implicaciones de Seguridad

*   **Usuario/Cliente al API Server:** Todos los comandos `kubectl` e interacciones de bibliotecas cliente. Deben ser autenticados y autorizados. TLS protege los datos en tránsito.
*   **API Server a Etcd:** El API Server es típicamente el único componente que habla directamente con `etcd`. Esta comunicación debe asegurarse con mTLS (TLS mutuo) y fuertes controles de acceso en `etcd`. `etcd` almacena todo el estado del clúster, incluidos los Secrets.
*   **Kubelet al API Server:** Los Kubelets vigilan las asignaciones de Pods e informan el estado del Nodo/Pod. Esta comunicación debe asegurarse con TLS y certificados de cliente del Kubelet. NodeRestriction y Node Authorizer limitan los permisos del Kubelet.
*   **Controller Manager/Scheduler al API Server:** Estos componentes observan y modifican el estado del clúster a través del API Server. Requieren permisos de cuenta de servicio (service account) apropiados (RBAC).
*   **Tráfico Pod-a-Pod:** Asegurado por Network Policies y potencialmente un service mesh para mTLS.
*   **Pod a Servicios Externos:** Tráfico de egreso. Puede ser controlado por Network Policies.

## Categorías Comunes de Amenazas y Ejemplos en Kubernetes

### Persistencia

Los atacantes buscan mantener el acceso a un sistema comprometido incluso después de reinicios o redespliegues.
*   **Cómo se Aplica a Kubernetes:**
    *   **Imágenes de Contenedor con Puertas Traseras (Backdoored):** Desplegar imágenes con código malicioso o shells inversas.
    *   **CronJobs en Pods/Namespaces Comprometidos:** Programar tareas maliciosas para que se ejecuten periódicamente.
    *   **Persistencia a Nivel de Nodo:** Si un atacante obtiene root en un nodo (por ejemplo, mediante un escape de contenedor), puede instalar malware persistente en el propio nodo (por ejemplo, servicios systemd, cron jobs).
    *   **Componentes del Plano de Control Comprometidos:** Modificar configuraciones o binarios del plano de control si un atacante obtiene acceso profundo.
    *   **Controladores de Admisión (Admission Controllers) o Webhooks Mutantes Maliciosos:** Inyectar sidecars maliciosos o modificar especificaciones de Pod para persistencia.
*   **Mitigaciones/Consideraciones:**
    *   Escaneo y firma de imágenes, uso de registros confiables.
    *   RBAC para limitar la creación de CronJobs.
    *   Fortalecimiento de la seguridad del nodo, monitorización de seguridad en tiempo de ejecución.
    *   Configuraciones seguras del plano de control, monitorización de integridad.
    *   Asegurar los webhooks de los controladores de admisión.

### Denegación de Servicio (DoS)

Hacer que los recursos o servicios no estén disponibles para los usuarios legítimos.
*   **Cómo se Aplica a Kubernetes:**
    *   **Agotamiento de Recursos (Cargas de Trabajo):**
        *   **CPU/Memoria:** Un Pod que consume toda la CPU/memoria disponible en un nodo, afectando a otros Pods o al Kubelet ("vecino ruidoso").
        *   **Ancho de Banda de Red:** Saturar los enlaces de red.
        *   **Agotamiento de PIDs:** Un proceso que crea demasiados PIDs en un nodo.
        *   **Espacio en Disco:** Llenar el espacio en disco del nodo (registros, almacenamiento efímero).
    *   **Ataques Contra Componentes del Plano de Control:**
        *   **API Server:** Sobrecargar con solicitudes excesivas (DoS a nivel de API).
        *   **Etcd:** Abrumar `etcd` con escrituras o lecturas, o corromper sus datos.
        *   **DNS:** Atacar CoreDNS/kube-dns.
*   **Mitigaciones/Consideraciones:**
    *   ResourceQuotas y LimitRanges para namespaces y Pods.
    *   Limitación de tasa (rate limiting) del API Server.
    *   Configuración segura y resiliente de `etcd` (dimensionamiento adecuado, aislamiento de red).
    *   Network Policies para limitar el tráfico.
    *   Horizontal Pod Autoscaler (HPA) y Cluster Autoscaler para manejar picos de carga legítimos.

### Ejecución de Código Malicioso y Aplicaciones Comprometidas en Contenedores

Ejecutar código no autorizado o explotar vulnerabilidades en aplicaciones contenerizadas.
*   **Cómo se Aplica a Kubernetes:**
    *   **Ejecución de Código Malicioso en un Contenedor:** Un atacante obtiene ejecución dentro de un contenedor existente (por ejemplo, a través de una vulnerabilidad de la aplicación como RCE) y ejecuta herramientas o scripts maliciosos.
    *   **Vulnerabilidades de Escape de Contenedor:** Explotar vulnerabilidades en el entorno de ejecución del contenedor, el kernel del host o configuraciones incorrectas (por ejemplo, contenedores privilegiados) para salir del aislamiento del contenedor y obtener acceso al nodo subyacente.
    *   **Movimiento Lateral desde un Contenedor Comprometido:** Una vez que un contenedor está comprometido, un atacante puede intentar:
        *   Acceder a otros Pods en el mismo nodo o red.
        *   Usar el token de la cuenta de servicio del Pod para interactuar con el API Server.
        *   Explotar vulnerabilidades en otros servicios del clúster.
*   **Mitigaciones/Consideraciones:**
    *   Prácticas de codificación segura, escaneo de vulnerabilidades para el código de la aplicación.
    *   Escaneo de imágenes, uso de imágenes base mínimas.
    *   Pod Security Standards (PSA) y `SecurityContext` (runAsNonRoot, drop capabilities, readOnlyRootFilesystem).
    *   Perfiles Seccomp, AppArmor, SELinux.
    *   Network Policies para limitar el movimiento lateral.
    *   Actualizar regularmente los entornos de ejecución y el SO del host.
    *   Monitorización de seguridad en tiempo de ejecución.

### Atacante en la Red

Explotar vulnerabilidades de red para interceptar, modificar o interrumpir la comunicación.
*   **Cómo se Aplica a Kubernetes:**
    *   **Ataques Man-in-the-Middle (MitM):** Si no se aplica TLS para la comunicación (por ejemplo, API Server, etcd, Kubelet, entre Pods), un atacante en la red podría interceptar y modificar el tráfico.
    *   **Escucha de Tráfico No Cifrado (Sniffing):** Capturar datos sensibles si la comunicación no está cifrada.
    *   **Ataques Contra CNI o la Infraestructura de Red:** Explotar vulnerabilidades en el plugin CNI o la infraestructura de red subyacente.
    *   **Suplantación ARP (ARP Spoofing), Suplantación DNS (DNS Spoofing):** Dentro de la red del clúster si no está adecuadamente segmentada o protegida.
*   **Mitigaciones/Consideraciones:**
    *   Aplicar TLS para toda la comunicación del plano de control y la API del Kubelet.
    *   Usar Network Policies para segmentar el tráfico.
    *   Considerar un service mesh (por ejemplo, Istio, Linkerd) para mTLS automático entre Pods.
    *   Asegurar el plugin CNI y mantenerlo actualizado.
    *   Monitorización de red y detección de intrusiones.

### Acceso a Datos Sensibles

Obtener acceso no autorizado a información confidencial.
*   **Cómo se Aplica a Kubernetes:**
    *   **Acceso No Autorizado a Kubernetes Secrets:** Leer Secrets directamente a través de la API (si RBAC está mal configurado) o desde un Pod comprometido que los tiene montados.
    *   **Acceso a Datos Sensibles en Volúmenes:** Si los Pods tienen acceso a PersistentVolumes con datos sensibles y están comprometidos.
    *   **Memoria de la Aplicación:** Datos sensibles (credenciales, PII) podrían estar presentes en la memoria de la aplicación dentro de un contenedor.
    *   **Fuga de Información a través de Registros o Metadatos:** Aplicaciones que registran datos sensibles, o metadatos expuestos (por ejemplo, a través del puerto de solo lectura del Kubelet, endpoints de Prometheus mal configurados).
    *   **Exposición de Datos de Etcd:** Acceso directo a `etcd` o sus copias de seguridad si no están asegurados.
*   **Mitigaciones/Consideraciones:**
    *   RBAC robusto para Secrets.
    *   Cifrado en reposo para `etcd` (protege los Secrets almacenados allí).
    *   Montar Secrets como archivos, no como variables de entorno.
    *   Mejores prácticas de manejo de datos a nivel de aplicación (por ejemplo, no registrar información sensible).
    *   Montajes de volúmenes seguros, usar cifrado de almacenamiento subyacente.
    *   Network Policies para restringir el acceso a servicios de datos.

### Escalada de Privilegios

Obtener niveles de permiso más altos de los autorizados inicialmente.
*   **Cómo se Aplica a Kubernetes:**
    *   **Explotación de RBAC Mal Configurado:** Un usuario/cuenta de servicio con permiso para crear/actualizar RoleBindings o ciertos recursos privilegiados podría escalar sus privilegios. El verbo `passimpersonate` también es peligroso.
    *   **Explotación de Configuraciones de Seguridad de Pod Excesivamente Permisivas:**
        *   Contenedores con `privileged: true`.
        *   Pods que montan rutas sensibles del host (`hostPath`).
        *   Pods que se ejecutan como root con capabilities excesivas.
    *   **Explotaciones del Kernel desde un Contenedor:** Si un contenedor puede explotar una vulnerabilidad del kernel, podría obtener acceso root en el nodo.
    *   **Compromiso de un Componente Privilegiado:** Obtener control del Kubelet, API Server o `etcd` usualmente significa el compromiso total del clúster.
    *   **Robo de Tokens:** Robar un token de cuenta de servicio más privilegiado de otro Pod o entorno.
*   **Mitigaciones/Consideraciones:**
    *   RBAC estricto, principio de menor privilegio.
    *   Aplicar Pod Security Standards robustos (Baseline/Restricted).
    *   Minimizar el uso del modo `privileged` y montajes `hostPath` sensibles.
    *   Ejecutar contenedores como usuarios no root, eliminar capabilities innecesarias.
    *   Mantener parcheados el kernel y todos los componentes de Kubernetes.
    *   Asegurar rigurosamente el Kubelet y los componentes del plano de control.

Comprender estas amenazas dentro del contexto de Kubernetes permite un enfoque más informado para el fortalecimiento del sistema, asegurando que las defensas se coloquen en los puntos más críticos.
