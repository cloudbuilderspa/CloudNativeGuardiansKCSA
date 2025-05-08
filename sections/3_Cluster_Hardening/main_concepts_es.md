# Conceptos Principales: Fundamentos de Seguridad de Kubernetes para el Fortalecimiento (Hardening) del Clúster

El fortalecimiento (hardening) del clúster implica aplicar un enfoque de seguridad por capas para reducir la superficie de ataque y minimizar las vulnerabilidades potenciales dentro de su entorno Kubernetes. Comprender e implementar los fundamentos de seguridad de Kubernetes es clave para lograr un clúster fortalecido. Esta sección cubre conceptos centrales esenciales para KCSA, basados en el dominio "Fundamentos de Seguridad de Kubernetes (22%)".

## Pod Security Standards (PSS) y Pod Security Admission (PSA)

**Concepto:**
*   **Pod Security Standards (PSS):** Definen tres niveles de políticas distintos para los Pods: `Privileged` (Privilegiado), `Baseline` (Base) y `Restricted` (Restringido). Estos estándares están diseñados para cubrir un amplio espectro de requisitos de seguridad.
    *   `Privileged`: Sin restricciones, permitiendo escaladas de privilegios conocidas. Solo debe usarse para cargas de trabajo confiables a nivel de sistema.
    *   `Baseline`: Mínimamente restrictivo, previniendo escaladas de privilegios conocidas mientras permite configuraciones comunes de aplicaciones. Es un buen punto de partida para la mayoría de las cargas de trabajo.
    *   `Restricted`: Altamente restrictivo, siguiendo las mejores prácticas actuales de fortalecimiento de Pods. Puede requerir refactorización de aplicaciones para compatibilidad.
*   **Pod Security Admission (PSA):** Un controlador de admisión (admission controller) incorporado en Kubernetes que aplica los PSS. PSA opera a nivel de namespace. Cuando está habilitado, puede configurar namespaces para `enforce` (aplicar), `audit` (auditar) o `warn` (advertir) durante la creación de Pods si no cumplen con un nivel PSS especificado.

**Importancia para el Fortalecimiento del Clúster:**
*   PSS y PSA son cruciales para evitar que los Pods se ejecuten con privilegios excesivos, lo cual es un vector común para escapes de contenedores y escalada de privilegios dentro del clúster.
*   Proporcionan una forma estandarizada de aplicar las mejores prácticas de seguridad a las cargas de trabajo de manera consistente en todos los namespaces.

**Mejores Prácticas Relevantes para KCSA:**
*   Comprender los diferentes niveles de PSS y sus implicaciones.
*   Saber cómo configurar PSA para namespaces para aplicar, auditar o advertir.
*   Intentar ejecutar cargas de trabajo en el nivel PSS más restrictivo posible (idealmente `Restricted` o `Baseline`).
*   Evitar usar el estándar `Privileged` a menos que sea absolutamente necesario para componentes específicos del sistema.

## Mecanismos de Autenticación

**Concepto:**
La autenticación es el proceso de verificar la identidad de un usuario, cuenta de servicio (service account) o proceso que intenta interactuar con el API Server de Kubernetes. Kubernetes no tiene un sistema de gestión de usuarios incorporado, sino que depende de métodos externos o autenticadores configurados.
Los métodos comunes incluyen:
*   **Certificados de Cliente:** Los usuarios o servicios presentan un certificado TLS firmado por la Autoridad de Certificación (CA) del clúster.
*   **Tokens Portadores (Bearer Tokens):** Una cadena presentada con las solicitudes API. Ejemplos incluyen tokens de Service Account (JWTs) o tokens de un proveedor OIDC.
*   **OpenID Connect (OIDC):** Se integra con proveedores de identidad externos (como Google, Okta, Dex) permitiendo a los usuarios autenticarse usando sus credenciales existentes.
*   **Autenticación por Webhook de Token:** Delega la verificación de tokens a un servicio externo.

**Importancia para el Fortalecimiento del Clúster:**
*   Una autenticación robusta asegura que solo entidades legítimas puedan intentar acceder al clúster.
*   Es la primera línea de defensa contra el acceso no autorizado.

**Mejores Prácticas Relevantes para KCSA:**
*   Deshabilitar la autenticación anónima (`--anonymous-auth=false` en el API Server).
*   Usar métodos de autenticación robustos; evitar archivos de contraseñas estáticas o autenticación básica para cuentas de usuario si es posible.
*   Para Service Accounts, usar tokens proyectados y de corta duración cuando sea factible (`TokenVolumeProjection`).
*   Gestionar de forma segura los certificados de cliente y los archivos kubeconfig.
*   Revisar y auditar regularmente los métodos de autenticación y el acceso de usuarios.

## Mecanismos de Autorización (Enfoque en RBAC)

**Concepto:**
La autorización determina si una entidad *autenticada* tiene permiso para realizar una acción específica (por ejemplo, crear un Pod, leer un Secret) sobre un recurso específico. Kubernetes utiliza principalmente el Control de Acceso Basado en Roles (RBAC).

*   **Componentes RBAC:**
    *   **Role:** Un conjunto de permisos dentro de un namespace específico. Define reglas que representan un conjunto de permisos (verbos: `get`, `list`, `create`, `update`, `delete`, etc.) sobre un conjunto de recursos (por ejemplo, `pods`, `services`, `secrets`).
    *   **ClusterRole:** Similar a un Role, pero su alcance es a nivel de todo el clúster. Puede otorgar permisos sobre recursos de alcance de clúster (como `nodes`) o sobre recursos dentro de namespaces en todos los namespaces.
    *   **RoleBinding:** Otorga los permisos definidos en un Role a un conjunto de usuarios, grupos o cuentas de servicio dentro de un namespace específico.
    *   **ClusterRoleBinding:** Otorga los permisos definidos en un ClusterRole a sujetos a nivel de todo el clúster.

**Importancia para el Fortalecimiento del Clúster:**
*   RBAC es fundamental para aplicar el Principio de Menor Privilegio, asegurando que los usuarios y las cargas de trabajo solo tengan los permisos que absolutamente necesitan.
*   Previene la escalada de privilegios y limita el radio de impacto si una cuenta o un token de cuenta de servicio se ven comprometidos.

**Mejores Prácticas Relevantes para KCSA:**
*   Siempre habilitar RBAC (`--authorization-mode=RBAC,...` en el API Server).
*   Seguir el Principio de Menor Privilegio: Otorgar los permisos mínimos necesarios.
*   Preferir Roles y RoleBindings (con alcance de namespace) sobre ClusterRoles y ClusterRoleBindings siempre que sea posible para limitar el alcance.
*   Evitar otorgar privilegios de `cluster-admin` a menos que sea estrictamente necesario y para un conjunto muy limitado de usuarios/cuentas.
*   Auditar regularmente las configuraciones RBAC en busca de roles o bindings excesivamente permisivos.
*   Usar cuentas de servicio específicas para aplicaciones en lugar de la cuenta de servicio `default`, y vincularlas a roles con privilegios mínimos.
*   Errores comunes: Vincular usuarios directamente a ClusterRoles como `cluster-admin`, usar permisos comodín (`*`) excesivamente en los roles.

## Gestión de Secrets

**Concepto:**
Los Kubernetes Secrets son objetos diseñados para almacenar y gestionar información sensible, como contraseñas, tokens OAuth y claves SSH. Permiten controlar cómo se utiliza la información sensible y reducir el riesgo de exposición accidental.

**Cómo se Almacenan los Secrets:**
*   Por defecto, los Secrets se almacenan en `etcd` como cadenas codificadas en base64. **Base64 es una codificación, no un cifrado.**
*   Para proteger los Secrets eficazmente, se debe habilitar el cifrado en reposo para los datos de `etcd`. El API Server maneja el cifrado/descifrado usando un proveedor de cifrado.

**Importancia para el Fortalecimiento del Clúster:**
*   Evita la codificación directa de datos sensibles en especificaciones de Pod, imágenes de contenedor o código de aplicación.
*   Proporciona una forma controlada de distribuir datos sensibles a los Pods.

**Mejores Prácticas Relevantes para KCSA:**
*   Habilitar el cifrado en reposo para `etcd`.
*   Usar RBAC para restringir el acceso a Secrets. Solo los usuarios y cuentas de servicio que necesiten un Secret específico deben tener permisos de `get`, `list` o `watch` sobre él.
*   Preferir montar Secrets como archivos en los Pods en lugar de como variables de entorno. Las variables de entorno pueden exponerse más fácilmente a través de registros o procesos hijos.
*   Evitar incluir manifiestos de Secret que contengan datos sensibles directamente en sistemas de control de versiones. Usar herramientas como Sealed Secrets o sistemas de gestión de secretos externos (por ejemplo, HashiCorp Vault, AWS Secrets Manager) para gestionar secretos en flujos de trabajo GitOps.
*   Auditar regularmente el acceso a Secrets y rotar los datos sensibles cuando sea apropiado.

## Aislamiento y Segmentación

**Concepto:**
El aislamiento y la segmentación son técnicas utilizadas para limitar el "radio de impacto" si un componente o carga de trabajo se ve comprometido. Previenen el movimiento lateral de los atacantes y aseguran que las cargas de trabajo solo tengan acceso a los recursos y rutas de red que necesitan.

*   **Namespaces:**
    *   Proporcionan un ámbito para los nombres de los recursos. Los recursos en un namespace están aislados de los recursos en otro (aunque no son una barrera de seguridad fuerte por sí mismos para el tráfico de red).
    *   Se utilizan para dividir los recursos del clúster entre múltiples usuarios o equipos.
    *   Los Roles RBAC tienen alcance de namespace, permitiendo un control de acceso detallado dentro de un namespace.
    *   Se pueden aplicar ResourceQuotas y LimitRanges por namespace.
*   **Network Policies (Políticas de Red):**
    *   Proporcionan segmentación de red L3/L4 para los Pods. Controlan cómo los Pods pueden comunicarse entre sí y con otros puntos finales de red.
    *   Las Network Policies son implementadas por el plugin CNI (Container Network Interface). No todos los plugins CNI admiten Network Policies.
    *   Por defecto, si no se aplica ninguna Network Policy a un Pod, se permite todo el tráfico de entrada (ingress) y salida (egress) hacia/desde ese Pod.
    *   **Mecánica Clave:**
        *   `podSelector`: Selecciona los Pods a los que se aplica la política.
        *   `policyTypes`: Indica si la política se aplica a `Ingress`, `Egress`, o ambos.
        *   Reglas `ingress`: Definen el tráfico entrante permitido.
        *   Reglas `egress`: Definen el tráfico saliente permitido.
        *   Las reglas pueden especificar orígenes/destinos usando `podSelector`, `namespaceSelector`, o `ipBlock`.
        *   Las reglas pueden especificar puertos y protocolos.

**Importancia para el Fortalecimiento del Clúster:**
*   Los Namespaces ayudan a organizar los recursos y aplicar políticas de seguridad distintas (RBAC, PSS, cuotas).
*   Las Network Policies son críticas para implementar un modelo de red de confianza cero (zero-trust) dentro del clúster, reduciendo el riesgo de movimiento lateral por parte de los atacantes.

**Mejores Prácticas Relevantes para KCSA:**
*   Usar namespaces para aislar diferentes aplicaciones, entornos (desarrollo, staging, producción) o equipos.
*   Implementar una Network Policy de denegación por defecto (default-deny) para los namespaces cuando sea apropiado, y luego permitir explícitamente el tráfico requerido.
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny-all
      namespace: my-secure-namespace # Reemplazar con su namespace
    spec:
      podSelector: {} # Selecciona todos los pods en el namespace
      policyTypes:
      - Ingress
      - Egress
      # La ausencia de reglas de ingress o egress significa que todo el tráfico está denegado
    ```
*   Definir Network Policies granulares para permitir solo la comunicación necesaria entre Pods y servicios.
*   Asegurar que su plugin CNI admita y aplique las Network Policies.

## Registro de Auditoría (Audit Logging)

**Concepto:**
El registro de auditoría proporciona un registro cronológico de las llamadas realizadas al API Server de Kubernetes. Cada entrada del registro de auditoría contiene información sobre quién realizó la solicitud, qué acción se realizó, qué recurso se vio afectado y el resultado.

**Importancia para el Fortalecimiento del Clúster:**
*   **Monitoreo de Seguridad:** Detectar actividad sospechosa, intentos de acceso no autorizado o violaciones de políticas.
*   **Respuesta a Incidentes:** Proporcionar un rastro de eventos para comprender cómo ocurrió un incidente de seguridad y qué se vio afectado.
*   **Cumplimiento:** Cumplir con los requisitos regulatorios u organizacionales de registro y auditoría.

**Mejores Prácticas Relevantes para KCSA:**
*   Habilitar el registro de auditoría en el API Server.
*   Configurar una política de auditoría apropiada para capturar eventos relevantes sin generar ruido excesivo. Aspectos clave de una política de auditoría:
    *   **Niveles (Levels):** `None`, `Metadata` (solo metadatos de la solicitud), `Request` (metadatos y cuerpo de la solicitud), `RequestResponse` (metadatos, cuerpo de la solicitud y cuerpo de la respuesta).
    *   **Etapas (Stages):** `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`. Registrar al menos `ResponseComplete`.
*   Almacenar los registros de auditoría de forma segura, preferiblemente en un sistema de registro centralizado fuera del clúster, con políticas de retención y controles de acceso apropiados.
*   Revisar regularmente los registros de auditoría o usar herramientas automatizadas para analizarlos en busca de anomalías.
*   Las acciones comúnmente auditadas incluyen la creación/eliminación/modificación de recursos, cambios en RBAC y acceso a Secrets.

Al dominar estos fundamentos de seguridad, puede fortalecer significativamente su clúster de Kubernetes, haciéndolo más resiliente contra amenazas y malas configuraciones comunes.

