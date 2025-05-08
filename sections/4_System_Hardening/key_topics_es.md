# Temas Clave: Modelo de Amenaza de Kubernetes y Fortalecimiento (Hardening) del Sistema

Esta sección amplía el Modelo de Amenaza de Kubernetes, profundizando en vectores de ataque específicos, métodos de persistencia avanzados y estrategias de defensa en profundidad. Una comprensión a nivel KCSA de estos temas es crucial para fortalecer proactivamente los sistemas Kubernetes contra amenazas del mundo real.

## Análisis Detallado de Vectores de Ataque

Comprender los vectores de ataque comunes ayuda a diseñar mejores defensas.

### Escenario: Volumen `hostPath` Mal Configurado que Conduce al Compromiso del Nodo

*   **Concepto:** Los volúmenes `hostPath` montan un archivo o directorio del sistema de archivos del nodo anfitrión en un Pod. Aunque a veces son necesarios, son peligrosos si no se restringen adecuadamente.
*   **Vector de Ataque:**
    1.  Un Pod se configura con un volumen `hostPath` que monta un directorio sensible del host (por ejemplo, `/`, `/etc`, `/var/lib/kubelet`, la ruta del socket de Docker como `/var/run/docker.sock`).
    2.  Si un atacante compromete este Pod (por ejemplo, a través de una vulnerabilidad de la aplicación), obtiene acceso de lectura/escritura a la ruta del host montada *desde dentro del contenedor*.
    3.  Con acceso a `/var/run/docker.sock`, un atacante puede controlar el daemon de Docker en el host, lanzar contenedores privilegiados y, efectivamente, tomar posesión del nodo.
    4.  El acceso a `/etc` podría permitir la modificación de archivos críticos del sistema o la lectura de datos sensibles. El acceso a los directorios del Kubelet podría llevar al robo de credenciales o al compromiso del Kubelet.
*   **Consideraciones y Mitigación KCSA:**
    *   **Limitar Estrictamente el Uso de `hostPath`:** Evitar los volúmenes `hostPath` siempre que sea posible.
    *   **Pod Security Standards (PSS):** Las políticas `Baseline` y `Restricted` restringen fuertemente o prohíben los volúmenes `hostPath` a rutas sensibles. Aplicar esto usando Pod Security Admission (PSA).
    *   **Montajes `readOnly`:** Si `hostPath` es inevitable, montarlo como `readOnly: true` si no se necesita acceso de escritura completo.
    *   **Montajes de Archivos Específicos:** Preferir montar archivos específicos en lugar de directorios completos si solo se necesita acceso a archivos.
    *   **RBAC:** Asegurar que solo usuarios/cuentas de servicio (service accounts) altamente confiables puedan crear Pods que puedan usar `hostPath`.

### Escenario: Explotación de una Aplicación Vulnerable para Acceso Inicial y Movimiento Lateral

*   **Concepto:** Un atacante explota una vulnerabilidad conocida (por ejemplo, RCE, SQLi, SSRF) en una aplicación que se ejecuta dentro de un contenedor para obtener acceso inicial al shell.
*   **Vector de Ataque (Post-Explotación):**
    1.  **Shell Inicial:** El atacante obtiene un shell dentro del contenedor comprometido.
    2.  **Recopilación de Información:**
        *   Verificar tokens de cuenta de servicio montados (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
        *   Inspeccionar variables de entorno en busca de datos sensibles.
        *   Escanear la red interna en busca de otros Pods/Servicios accesibles.
    3.  **Movimiento Lateral usando Token de Service Account:** Si la cuenta de servicio del Pod tiene permisos RBAC excesivos, el atacante puede usar el token con `kubectl` (si está disponible o se carga) o llamadas API directas para:
        *   Listar Secrets en el namespace o en todo el clúster.
        *   Crear nuevos Pods (potencialmente privilegiados o con puertas traseras).
        *   Ejecutar `exec` en otros Pods.
    4.  **Movimiento Lateral Basado en Red:** Si las Network Policies no son restrictivas, el atacante puede escanear e intentar explotar otros servicios que se ejecutan dentro de la red del clúster.
*   **Consideraciones y Mitigación KCSA:**
    *   **Seguridad de Aplicaciones:** Codificación segura, escaneo de dependencias, firewalls de aplicaciones web (WAFs).
    *   **Menor Privilegio (RBAC):** Asignar permisos mínimos a las cuentas de servicio.
    *   **Network Policies:** Implementar denegación por defecto y permitir solo el tráfico necesario entre Pods.
    *   **Pod Security Standards/`SecurityContext`:** Ejecutar contenedores como no-root, eliminar capabilities, usar sistemas de archivos raíz de solo lectura para limitar las capacidades del atacante incluso si obtiene un shell.
    *   **Monitorización de Seguridad en Tiempo de Ejecución:** Detectar actividad sospechosa dentro de los contenedores.

### Escenario: Abuso de RBAC Excesivamente Permisivo para Escalada de Privilegios

*   **Concepto:** Las configuraciones incorrectas de RBAC son un objetivo principal para que los atacantes escalen privilegios.
*   **Vector de Ataque:**
    1.  Un atacante compromete una cuenta de usuario o cuenta de servicio con ciertos permisos RBAC aparentemente inocuos.
    2.  Estos permisos, sin embargo, permiten al atacante otorgarse a sí mismo o a otra identidad controlada permisos más poderosos. Ejemplos:
        *   Permiso para crear/actualizar `(Cluster)RoleBindings`: El atacante puede vincular su cuenta controlada a `cluster-admin`.
        *   Permiso para crear/actualizar `(Cluster)Roles`: El atacante puede agregar permisos comodín (`*` sobre `*`) a un rol que controla o al que está vinculado.
        *   Permiso para usar el verbo `passimpersonate` sobre un usuario/grupo privilegiado.
        *   Permiso para crear Pods con `hostPID: true` o `hostIPC: true` que pueden usarse para obtener acceso al nodo o interferir con otros procesos.
        *   Permiso para crear Pods que pueden usar cuentas de servicio específicas que son altamente privilegiadas.
*   **Consideraciones y Mitigación KCSA:**
    *   **Auditorías RBAC Regulares:** Revisar periódicamente todos los Roles, ClusterRoles, RoleBindings y ClusterRoleBindings.
    *   **Principio de Menor Privilegio:** Adherirse estrictamente a otorgar solo los permisos necesarios.
    *   **Restringir la Modificación de Objetos RBAC:** Solo los administradores altamente confiables deberían poder modificar los recursos RBAC.
    *   **Monitorear Registros de Auditoría:** Vigilar la creación/modificación de recursos RBAC y eventos de suplantación sospechosos.

## Técnicas Avanzadas de Persistencia en Kubernetes

Los atacantes utilizan varios métodos para mantener el acceso a largo plazo.

### Uso de Webhooks de Admisión Mutantes (Mutating Admission Webhooks)

*   **Concepto:** Los Webhooks de Admisión Mutantes pueden modificar objetos enviados al API Server antes de que se almacenen.
*   **Técnica de Persistencia:** Si un atacante puede crear o comprometer un Webhook de Admisión Mutante, puede configurarlo para:
    *   Inyectar un contenedor sidecar malicioso en cada nuevo Pod creado en ciertos namespaces.
    *   Modificar las especificaciones de los Pods para montar rutas sensibles del host o usar contextos de seguridad privilegiados.
    *   Agregar variables de entorno con comandos de puerta trasera.
*   **Mitigación:**
    *   Asegurar rigurosamente los endpoints del servidor webhook (TLS, authN, authZ).
    *   RBAC: Controlar estrictamente quién puede crear o modificar objetos `MutatingWebhookConfiguration`.
    *   Monitorear los registros de auditoría para detectar cambios en las configuraciones de los webhooks de admisión.
    *   Revisión de código y prácticas de despliegue seguras para los servidores webhook.

### Aprovechamiento de `initContainers` o Sidecars en Deployments/DaemonSets Comprometidos

*   **Concepto:** Si un atacante compromete una definición de Deployment, StatefulSet o DaemonSet (por ejemplo, mediante el compromiso del pipeline CI/CD o acceso directo a la API con suficientes privilegios), puede agregar `initContainers` o contenedores sidecar maliciosos.
*   **Técnica de Persistencia:**
    *   El contenedor malicioso se ejecuta junto con el contenedor de la aplicación legítima.
    *   Puede exfiltrar datos, proporcionar un shell inverso o actuar como punto de pivote.
    *   Dado que es parte de la definición de la carga de trabajo, se volverá a desplegar automáticamente si se recrean los Pods.
*   **Mitigación:**
    *   GitOps: Usar control de versiones y procesos de revisión para todos los manifiestos de Kubernetes.
    *   RBAC: Restringir el acceso de escritura a los controladores de carga de trabajo.
    *   Seguridad de imágenes: Asegurar que todos los contenedores (incluidos init y sidecars) provengan de fuentes confiables y estén escaneados.
    *   Seguridad en tiempo de ejecución: Monitorear el comportamiento de todos los contenedores.

## Defensa en Profundidad contra la Escalada de Privilegios

Prevenir la escalada de privilegios requiere múltiples capas de controles de seguridad.

*   **Concepto:** La defensa en profundidad significa aplicar múltiples controles de seguridad superpuestos para que, si un control falla, otros sigan activos para frustrar un ataque.
*   **Capas Clave en Kubernetes:**
    1.  **Autenticación y Autorización Robustas (RBAC):** La primera puerta. Asegurar el menor privilegio para todos los usuarios y cuentas de servicio.
    2.  **Pod Security Admission (PSA):** Aplicar los Pod Security Standards `Baseline` o `Restricted` para limitar lo que los Pods pueden hacer por defecto (por ejemplo, prevenir la ejecución como root, uso de hostPID/hostNetwork, capabilities privilegiadas).
    3.  **`SecurityContext`:** Ajustar finamente la configuración de seguridad dentro de Pods y contenedores (por ejemplo, `runAsUser`, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`).
    4.  **Network Policies:** Restringir el acceso a la red para limitar el movimiento lateral y el acceso a servicios sensibles, incluso si un Pod está comprometido.
    5.  **Seguridad en Tiempo de Ejecución (Seccomp, AppArmor, SELinux):** Restringir aún más las acciones de los contenedores a nivel del kernel filtrando syscalls y controlando el acceso a los recursos.
    6.  **Fortalecimiento del Nodo (Node Hardening):** Asegurar el SO anfitrión subyacente de los nodos trabajadores (minimizar paquetes instalados, aplicar parches de seguridad, usar MAC como SELinux).
    7.  **Entornos de Ejecución de Contenedores Seguros:** Mantener los entornos de ejecución parcheados y configurados de forma segura.
    8.  **Registro de Auditoría y Monitorización:** Detectar intentos de escalada de privilegios o actividades sospechosas.
*   **Relevancia para KCSA:** Comprender que ningún control de seguridad único es infalible. La seguridad por capas aumenta significativamente la dificultad para que un atacante escale privilegios y comprometa el clúster.

## Rol de la Segmentación de Red en la Mitigación de Amenazas de Red

Las Network Policies son una piedra angular de la seguridad de la red dentro del clúster.

*   **Prevención de Sniffing/MitM dentro del Clúster:**
    *   Aunque las Network Policies operan en L3/L4, pueden limitar qué Pods pueden siquiera intentar comunicarse con un Pod objetivo. Si un atacante compromete `Pod-A`, y a `Pod-A` no se le permite hablar con `Pod-B` (que maneja datos sensibles), entonces el atacante no puede hacer sniffing o MitM directamente del tráfico de `Pod-B` desde `Pod-A`.
    *   Para un verdadero cifrado del tráfico entre Pods (protegiendo contra un nodo comprometido o un atacante de red sofisticado), se necesita un service mesh (por ejemplo, Istio, Linkerd) que proporcione mTLS. Las Network Policies complementan esto definiendo *quién* puede hablar, mientras que mTLS asegura *cómo* hablan.
*   **Uso de Políticas de Egreso para la Prevención de Exfiltración de Datos y C2:**
    *   **Concepto:** Las políticas de egreso controlan las conexiones salientes *desde* los Pods.
    *   **Prevención de Exfiltración de Datos:** Por defecto, los Pods a menudo pueden conectarse a cualquier dirección IP en Internet. Un Pod comprometido podría exfiltrar datos sensibles. Las políticas de egreso pueden restringir las conexiones salientes solo a endpoints externos conocidos y legítimos (por ejemplo, servicios de bases de datos específicos, APIs de socios).
    *   **Prevención de Comando y Control (C2):** El malware a menudo intenta conectarse de nuevo al servidor C2 de un atacante. Las políticas de egreso restrictivas pueden bloquear estas conexiones C2 salientes.
    *   **Ejemplo: Denegar todo el egreso, luego permitir específico:**
        ```yaml
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-egress
          namespace: my-app-ns # Reemplazar con su namespace
        spec:
          podSelector: {}
          policyTypes:
          - Egress # Esta política solo afecta al Egress
          # La ausencia de reglas de egress significa que todo el egress está denegado
        ---
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: allow-dns-and-specific-external
          namespace: my-app-ns # Reemplazar con su namespace
        spec:
          podSelector:
            matchLabels:
              app: my-critical-app
          policyTypes:
          - Egress
          egress:
          - to: # Permitir DNS a CoreDNS
            - namespaceSelector:
                matchLabels:
                  kubernetes.io/metadata.name: kube-system
              podSelector:
                matchLabels:
                  k8s-app: kube-dns
            ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          - to: # Permitir acceso a un servicio externo específico
            - ipBlock:
                cidr: 203.0.113.45/32
            ports:
            - port: 443
              protocol: TCP
        ```
*   **Relevancia para KCSA:** El uso efectivo de Network Policies (tanto de ingreso como de egreso) es crítico para limitar el radio de impacto de un ataque basado en red o un Pod comprometido.

## Aplicación Conceptual de Frameworks de Modelado de Amenazas (por ejemplo, STRIDE)

*   **Concepto:** STRIDE (Suplantación de Identidad, Manipulación de Datos, Repudio, Divulgación de Información, Denegación de Servicio, Elevación de Privilegios) es un framework común para categorizar e identificar amenazas.
*   **Aplicación de STRIDE a un Componente de Kubernetes (por ejemplo, Kubelet - Conceptual):**
    *   **Suplantación de Identidad (Spoofing):** ¿Podría un atacante suplantar la identidad del Kubelet ante el API Server? (Mitigación: Certificados de cliente robustos para el Kubelet). ¿Podría un Pod malicioso suplantar la identidad de otro Pod ante el Kubelet?
    *   **Manipulación de Datos (Tampering):** ¿Podría un atacante manipular los datos que el Kubelet envía al API Server (estado del Pod)? (Mitigación: TLS). ¿Podrían manipular la configuración del Kubelet en el nodo? (Mitigación: Fortalecimiento del nodo, monitorización de integridad de archivos).
    *   **Repudio (Repudiation):** ¿El Kubelet registra sus acciones suficientemente para la auditoría? ¿Se pueden rastrear las acciones?
    *   **Divulgación de Información (Information Disclosure):** ¿La API del Kubelet (puerto 10250/10255) filtra información sensible si está mal configurada? (Mitigación: Deshabilitar la autenticación anónima, restringir el puerto de solo lectura).
    *   **Denegación de Servicio (Denial of Service):** ¿Puede el Kubelet ser abrumado por demasiados Pods o solicitudes API, impactando la estabilidad del nodo? (Mitigación: Límites de recursos del nodo, control de admisión del API server).
    *   **Elevación de Privilegios (Elevation of Privilege):** Si el Kubelet se ve comprometido, ¿puede un atacante obtener root en el nodo o controlar otros Pods? (Mitigación: Ejecutar Kubelet con el menor privilegio posible, controlador de admisión NodeRestriction).
*   **Relevancia para KCSA:** Aunque la aplicación profunda de STRIDE es avanzada, comprender que tales frameworks existen y ayudan a pensar sistemáticamente sobre las amenazas a componentes como Kubelet, API Server, o incluso aplicaciones desplegadas, es valioso para una mentalidad de seguridad.

## Ataques a la Cadena de Suministro (Supply Chain Attacks) como Vector de Amenaza

*   **Concepto:** Ataques que apuntan al ciclo de vida de desarrollo de software (construcción, prueba, empaquetado, despliegue) para inyectar código malicioso o comprometer dependencias.
*   **Relevancia para el Modelo de Amenaza de Kubernetes:**
    *   **Imágenes de Contenedor Comprometidas:** Un atacante podría empujar una imagen maliciosa a un registro público o privado, o comprometer una imagen legítima inyectando malware. Si estas imágenes se obtienen y ejecutan en el clúster, proporcionan un punto de apoyo inicial.
    *   **Dependencias Vulnerables:** Las aplicaciones a menudo utilizan muchas bibliotecas de terceros. Una vulnerabilidad en una de estas dependencias (por ejemplo, Log4Shell) puede ser explotada una vez que la aplicación está contenerizada y desplegada.
*   **Mitigación (Enlaces al Dominio de Seguridad de la Cadena de Suministro):**
    *   Escaneo de imágenes en busca de vulnerabilidades.
    *   Uso de imágenes base confiables/verificadas.
    *   Firma y verificación de imágenes (por ejemplo, Notary, Sigstore).
    *   Lista de Materiales de Software (SBOM - Software Bill of Materials) para rastrear dependencias.
    *   Pipelines CI/CD seguros con verificaciones y controles.
*   **Relevancia para KCSA:** Reconocer que las amenazas pueden originarse *antes* de que las cargas de trabajo lleguen al clúster es importante. La integridad de las imágenes de contenedor y las dependencias de las aplicaciones forma parte del panorama general de amenazas.

Comprender estos temas clave ayuda a desarrollar una estrategia de seguridad proactiva y por capas para Kubernetes, lo cual es esencial para mitigar los riesgos identificados a través del modelado de amenazas.

