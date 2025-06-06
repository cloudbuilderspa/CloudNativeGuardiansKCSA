---
layout: default
title: Guía de Laboratorio
parent: "2. Configuración del Clúster"
nav_order: 3
permalink: /es/sections/2-configuracion-cluster/guia-laboratorio/
lang: es
---
# Guía de Laboratorio: Seguridad de los Componentes del Clúster de Kubernetes

Esta guía de laboratorio proporciona ejercicios prácticos para ayudarle a comprender y aplicar conceptos de seguridad relacionados con los componentes del clúster de Kubernetes. Estos ejercicios están diseñados para un nivel de comprensión KCSA y asumen que usted tiene acceso `kubectl` a un clúster de Kubernetes (como Minikube, Kind o un clúster gestionado en la nube donde tenga los permisos apropiados).

**Nota:** Algunos comandos, especialmente aquellos que inspeccionan las configuraciones de los componentes del plano de control, podrían requerir acceso al nodo o configuraciones específicas que varían entre distribuciones de Kubernetes y servicios gestionados. Adapte los comandos según sea necesario para su entorno.

## Ejercicio 1: Inspección de Seguridad del API Server

**Objetivo:** Inspeccionar configuraciones de seguridad clave del API Server de Kubernetes.

**Instrucciones:**


**Punto de Predicción:** Antes de inspeccionar el manifiesto del API Server, ¿qué modos de autorización *espera* ver habilitados para una buena seguridad en un clúster de Kubernetes? ¿Por qué se incluye comúnmente RBAC?
1.  **Verificar Flags de Autenticación y Autorización del API Server:**
    *   Si tiene acceso al(los) nodo(s) del plano de control, puede inspeccionar el archivo de manifiesto del API Server. Para Minikube, puede acceder por SSH a la VM de Minikube:
        ```bash
        minikube ssh
        sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml
        ```
    *   Busque flags como:
        *   `--anonymous-auth`: Idealmente debería ser `false`.
        *   `--authorization-mode`: Debería incluir `Node,RBAC` (u otros autorizadores según corresponda).
        *   `--client-ca-file`: Especifica la CA para la autenticación por certificado de cliente.
        *   `--tls-cert-file` y `--tls-private-key-file`: Especifican el certificado del servidor y la clave privada para TLS.

**Punto de Verificación:** Si `--anonymous-auth` estuviera configurado en `true` (no recomendado), ¿cómo cambiaría eso la postura de seguridad del clúster con respecto al acceso no autenticado?
    *   **Resultado Esperado:** Debería poder identificar cómo están configuradas la autenticación y la autorización.
    *   **Nota de Seguridad:** Estos flags definen configuraciones de seguridad fundamentales. Una mala configuración puede llevar a accesos no autorizados.

2.  **Inspeccionar Roles RBAC y ClusterRoles:**
    *   Listar todos los ClusterRoles:
        ```bash
        kubectl get clusterroles
        ```
    *   Describir un rol potencialmente demasiado permisivo como `cluster-admin`:
        ```bash
        kubectl describe clusterrole cluster-admin
        ```
    *   Listar todos los RoleBindings y ClusterRoleBindings:
        ```bash
        kubectl get rolebindings --all-namespaces
        kubectl get clusterrolebindings
        ```
    *   **Resultado Esperado:** Comprensión de cómo los roles y los bindings otorgan permisos. Podría identificar sujetos (usuarios, grupos, cuentas de servicio) vinculados a roles poderosos.
    *   **Nota de Seguridad:** RBAC es crítico. Audite regularmente los roles y bindings para asegurar que se mantenga el principio de menor privilegio.

**Tarea de Desafío:**
Escriba el manifiesto YAML para un `Role` llamado `lector-configmap` en el namespace `default` que permita a un sujeto únicamente hacer `get` y `list` de ConfigMaps.
<details>
  <summary>Haga clic para ver una posible solución</summary>
  <p>

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    namespace: default
    name: lector-configmap
  rules:
  - apiGroups: [""] # "" indica el grupo API principal (core)
    resources: ["configmaps"]
    verbs: ["get", "list"]
  ```
  </p>
</details>

3.  **Verificar el Estado de la Autenticación Anónima (Indirectamente):**
    *   Intente acceder a un endpoint común de la API sin credenciales. Si la autenticación anónima está deshabilitada (que es lo predeterminado y recomendado), debería recibir un error de no autorizado.
        ```bash
        # Este comando probablemente fallará si se ejecuta desde fuera del clúster sin un proxy
        # o un kubeconfig adecuado. Si tiene curl dentro de un pod:
        # curl -k https://kubernetes.default.svc/api/v1/pods
        # Una prueba más directa sería configurar kubectl sin usuario e intentarlo.
        # Para este laboratorio, concéntrese en la inspección del flag --anonymous-auth.
        ```
    *   **Resultado Esperado:** Confirmación (principalmente mediante la inspección de flags) de que el acceso anónimo está deshabilitado.
    *   **Nota de Seguridad:** El acceso anónimo proporciona un punto de entrada no autenticado y casi siempre debe estar deshabilitado.

## Ejercicio 2: Seguridad del Kubelet

**Objetivo:** Comprender la seguridad de la API del Kubelet y su exposición.

**Instrucciones:**


**Punto de Predicción:** La API del Kubelet en el puerto 10250 es poderosa. ¿Qué tipo de mecanismos de autenticación y autorización esperaría que estuvieran habilitados por defecto en este puerto para protegerlo? ¿Por qué es peligroso el acceso no restringido a este puerto?
1.  **Intentar Acceder a la API del Kubelet (Puerto 10250):**
    *   Primero, obtenga la dirección IP de uno de sus nodos:
        ```bash
        kubectl get nodes -o wide
        ```
    *   Si puede ejecutar `exec` en un pod que se ejecuta en ese nodo, o si tiene acceso de red al puerto 10250 del nodo, intente acceder al endpoint `/pods` del Kubelet. Reemplace `NODE_IP` con la IP real.
        ```bash
        # Ejemplo desde dentro de un pod que puede alcanzar el nodo:
        # curl -k https://NODE_IP:10250/pods
        ```
        O, usando `kubectl proxy` y `kubectl get --raw`:
        ```bash
        kubectl proxy &
        # Obtener un nombre de nodo
        NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
        kubectl get --raw "/api/v1/nodes/${NODE_NAME}/proxy/pods"
        # Terminar el proxy: fg luego Ctrl+C
        ```
    *   **Resultado Esperado:** Si la autenticación/autorización del Kubelet está habilitada (predeterminado), debería obtener un error de no autorizado o se le solicitarán credenciales si accede directamente. Si usa `kubectl get --raw` a través del proxy, utiliza sus credenciales de `kubectl`, que probablemente estén autorizadas. Esto demuestra un acceso seguro.
    *   **Nota de Seguridad:** La API del Kubelet (10250) debe estar protegida por autenticación y autorización.

2.  **Discusión sobre el Puerto de Solo Lectura (10255):**
    *   El Kubelet *solía* exponer un puerto de solo lectura (10255) para métricas y estado, que no requería autenticación. Esto generalmente está deshabilitado o restringido en las versiones modernas de Kubernetes.
    *   Para verificar si está activo en un nodo al que tiene acceso, podría intentar:
        ```bash
        # Desde una máquina que pueda alcanzar NODE_IP o desde dentro de un pod en ese nodo:
        # curl http://NODE_IP:10255/pods
        ```
    *   **Discusión:** ¿Por qué un puerto de solo lectura no autenticado es un riesgo de seguridad? (Divulgación de información sobre cargas de trabajo y configuración del nodo).
    *   **Nota de Seguridad:** Asegúrese de que el puerto 10255 esté deshabilitado o protegido por firewall si no se necesita y si existe en su versión.

**Tarea de Desafío:**
¿Cómo podría verificar conceptualmente si un Kubelet en un nodo específico está configurado con `readOnlyPort: 0` (lo que deshabilita el puerto de solo lectura)? Piense dónde podría almacenarse la configuración del Kubelet o cómo se pasa al proceso Kubelet.
<details>
  <summary>Haga clic para ver un posible enfoque</summary>
  <p>
  Un enfoque sería inspeccionar el archivo de configuración del Kubelet en el nodo. La ubicación de este archivo puede variar, pero a menudo es `/var/lib/kubelet/config.yaml`. Buscaría la configuración `readOnlyPort` dentro de este archivo. Alternativamente, si el Kubelet se ejecuta como un servicio systemd, sus flags de inicio (que podrían incluir `--read-only-port=0`) podrían inspeccionarse en el archivo de la unidad systemd. La inspección directa típicamente requiere acceso al nodo.
  </p>
</details>

## Ejercicio 3: Seguridad de Etcd (Conceptual/Verificación)

**Objetivo:** Comprender cómo se configura típicamente la seguridad de `etcd`. El acceso directo a `etcd` suele estar restringido y no disponible para usuarios típicos.

**Instrucciones:**


**Punto de Predicción:** El almacén de datos `etcd` contiene todo el estado del clúster, incluidos los Secrets. ¿Por qué es absolutamente crítico asegurar el canal de comunicación entre el API Server y `etcd`? ¿Qué tipo de ataque podría ocurrir si este canal no estuviera cifrado o autenticado?
1.  **Verificar Comunicación con Etcd sobre TLS (Configuración del API Server):**
    *   Inspeccione el manifiesto de su API Server (como en el Ejercicio 1.1).
    *   Busque flags relacionados con la comunicación con `etcd`:
        *   `--etcd-servers`: Debería listar URLs de servidores `etcd` usando `https://`.
        *   `--etcd-cafile`: Certificado CA para verificar los certificados del servidor `etcd`.
        *   `--etcd-certfile` y `--etcd-keyfile`: Certificado de cliente y clave para que el API Server se autentique en `etcd`.
    *   **Resultado Esperado:** Confirmación de que el API Server está configurado para comunicarse con `etcd` sobre TLS usando autenticación mutua.
    *   **Nota de Seguridad:** Cifrar la comunicación entre el API Server y `etcd` es crucial para proteger los datos de estado del clúster en tránsito.

2.  **Revisar Configuraciones de Cifrado en Reposo de Etcd (Configuración del API Server):**
    *   En el manifiesto del API Server, busque el flag `--encryption-provider-config`.
    *   Si este flag está presente y configurado, significa que el cifrado en reposo para los datos de `etcd` (especialmente Secrets) está habilitado. El archivo de configuración referenciado detallaría los proveedores de cifrado (por ejemplo, `aescbc`, `kms`).
    *   **Resultado Esperado:** Comprensión de si y cómo está configurado el cifrado en reposo para `etcd`. En muchos servicios de Kubernetes gestionados, esto lo maneja el proveedor.
    *   **Nota de Seguridad:** Cifrar datos sensibles como Secrets en reposo en `etcd` es una medida de seguridad crítica.

**Tarea de Desafío:**
Si un atacante obtuviera acceso de lectura a los archivos de datos brutos de `etcd` (por ejemplo, desde una copia de seguridad comprometida o acceso directo al sistema de archivos en un nodo `etcd`) y el cifrado en reposo de `etcd` *no* estuviera habilitado, ¿qué objetos sensibles de Kubernetes podría reconstruir o leer directamente?
<details>
  <summary>Haga clic para ver ejemplos clave</summary>
  <p>
  Potencialmente podría reconstruir o leer:
  <ul>
    <li>Todos los Kubernetes Secrets (que por defecto solo están codificados en base64 en etcd).</li>
    <li>Tokens de Service Account.</li>
    <li>ConfigMaps que contengan configuración sensible.</li>
    <li>La configuración completa de todos los objetos API (Pods, Deployments, Services, etc.).</li>
  </ul>
  Esto llevaría a un compromiso total del clúster.
  </p>
</details>

## Ejercicio 4: Contexto de Seguridad del Pod (Pod Security Context)

**Objetivo:** Aplicar y observar los efectos de las configuraciones de `SecurityContext` en los Pods.

**Instrucciones:**


**Punto de Predicción:** Al buscar el principio de menor privilegio, ¿qué configuraciones de `securityContext` considera más cruciales para definir en un Pod y sus contenedores? Considere las configuraciones relacionadas con la identidad del usuario y el acceso al sistema de archivos.
1.  **Desplegar un Pod con un `SecurityContext` Restrictivo:**
    *   Cree un archivo YAML (por ejemplo, `restricted-pod.yaml`):
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: restricted-pod
        spec:
          securityContext:
            runAsUser: 1000
            runAsGroup: 3000
            fsGroup: 2000
            runAsNonRoot: true
          containers:
          - name: main-container
            image: alpine
            command: ["sh", "-c", "sleep 1h && id && ls -ld /data"]
            securityContext:
              readOnlyRootFilesystem: true
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                - "ALL"
            volumeMounts:
            - name: data-vol
              mountPath: /data
          volumes:
          - name: data-vol
            emptyDir: {}
        ```
    *   Aplique el manifiesto: `kubectl apply -f restricted-pod.yaml`
    *   Verifique el estado y los registros del Pod:
        ```bash
        kubectl get pod restricted-pod
        kubectl logs restricted-pod
        # Después de un tiempo, o ejecute exec si se ejecuta el tiempo suficiente
        kubectl exec -it restricted-pod -- sh
        # Dentro del pod, intente:
        # id
        # touch /test.txt (debería fallar)
        # touch /data/test-data.txt (debería tener éxito, verifique los permisos de fsGroup más tarde)
        ```
    *   **Resultado Esperado:** El Pod debería ejecutarse correctamente. Los comandos dentro del contenedor deberían reflejar `runAsUser` y `runAsGroup`. El sistema de archivos raíz debería ser de solo lectura.
    *   **Nota de Seguridad:** `SecurityContext` es vital para aplicar el principio de menor privilegio para las cargas de trabajo.

**Punto de Verificación:**
En `restricted-pod.yaml`, se configuró `readOnlyRootFilesystem: true` para el contenedor. Si ejecuta `exec` en el `restricted-pod` (una vez que esté en ejecución y los comandos estén disponibles), ¿qué comando podría intentar ejecutar para confirmar que el sistema de archivos raíz es efectivamente de solo lectura? ¿Qué error esperaría?
<details>
  <summary>Haga clic para ver una sugerencia</summary>
  <p>
  Podría intentar un comando como `touch /test-file.txt`. Esperaría un mensaje de error similar a "Read-only file system" (Sistema de archivos de solo lectura).
  </p>
</details>

2.  **Observar un Pod Fallando Debido a `runAsNonRoot` (si la imagen se ejecuta como root):**
    *   Cree `violating-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: violating-pod
        spec:
          securityContext:
            runAsNonRoot: true # Forzar no-root
          containers:
          - name: main-container
            image: nginx # La imagen oficial de Nginx se ejecuta como root por defecto
            command: ["sleep", "3600"]
        ```
    *   Aplique: `kubectl apply -f violating-pod.yaml`
    *   Verifique el estado: `kubectl get pod violating-pod -w`
    *   Describa el pod para ver eventos: `kubectl describe pod violating-pod`
    *   **Resultado Esperado:** El Pod debería fallar al iniciarse (por ejemplo, `CreateContainerError` o estado similar). Los eventos deberían indicar una violación de restricción del contexto de seguridad porque la imagen intenta ejecutarse como root.
    *   **Nota de Seguridad:** Esto demuestra cómo `runAsNonRoot` puede evitar que las imágenes se ejecuten como root. Esto a menudo requiere que las imágenes estén construidas para admitir la ejecución como usuarios no root.

**Tarea de Desafío:**
Imagine que tiene un Dockerfile para una aplicación que, por defecto, ejecuta su proceso principal como root. ¿Qué cambios necesitaría hacer en el Dockerfile para permitir que se ejecute correctamente cuando se establecen `runAsNonRoot: true` y un `runAsUser: 1001` específico en el `securityContext` del Pod?
<details>
  <summary>Haga clic para ver consideraciones clave del Dockerfile</summary>
  <p>
  Las consideraciones clave en el Dockerfile incluirían:
  <ul>
    <li>Crear un usuario y grupo no root (por ejemplo, `RUN addgroup -S appgroup && adduser -S appuser -G appgroup`).</li>
    <li>Asegurar que los archivos de la aplicación y cualquier directorio en el que la aplicación necesite escribir (como directorios temporales o de registro dentro del contenedor) sean propiedad de este `appuser:appgroup` (por ejemplo, usando `COPY --chown=appuser:appgroup . /app` o `RUN chown -R appuser:appgroup /alguna/ruta`).</li>
    <li>Cambiar a este usuario usando la instrucción `USER appuser` antes del `CMD` o `ENTRYPOINT`.</li>
  </ul>
  </p>
</details>

## Ejercicio 5: Seguridad de Tokens de Service Account

**Objetivo:** Comprender y gestionar el uso de tokens de Service Account en Pods.

**Instrucciones:**


**Punto de Predicción:** Por defecto, Kubernetes monta un token de Service Account en cada Pod. ¿Qué tipo de información contiene este token (típicamente un JWT) y por qué cree que existe este comportamiento predeterminado?
1.  **Inspeccionar Token de Service Account Predeterminado en un Pod:**
    *   Despliegue un Pod simple: `kubectl run test-pod --image=busybox --restart=Never -- sh -c "sleep 3600"`
    *   Ejecute `exec` en el Pod: `kubectl exec -it test-pod -- sh`
    *   Dentro del Pod, inspeccione el token predeterminado:
        ```sh
        ls /var/run/secrets/kubernetes.io/serviceaccount/
        cat /var/run/secrets/kubernetes.io/serviceaccount/token
        ```
    *   **Resultado Esperado:** Verá los archivos `token`, `ca.crt` y `namespace`. El token es un JWT.
    *   **Nota de Seguridad:** Por defecto, los Pods obtienen un token para la cuenta de servicio `default` en su namespace. Este token podría tener más permisos de los necesarios.

2.  **Crear un Pod que NO Monte Automáticamente el Token de Service Account:**
    *   Cree `no-token-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: no-token-pod
        spec:
          automountServiceAccountToken: false
          containers:
          - name: main
            image: busybox
            command: ["sleep", "3600"]
        ```
    *   Aplique: `kubectl apply -f no-token-pod.yaml`
    *   Ejecute `exec` en `no-token-pod` y verifique:
        ```bash
        kubectl exec -it no-token-pod -- sh
        ls /var/run/secrets/kubernetes.io/serviceaccount/
        ```
    *   **Resultado Esperado:** El directorio `/var/run/secrets/kubernetes.io/serviceaccount/` no debería existir o estar vacío.
    *   **Nota de Seguridad:** Si un Pod no necesita interactuar con el API Server, deshabilite el montaje automático de tokens.

**Punto de Verificación:**
¿Puede pensar en ejemplos de cargas de trabajo o aplicaciones que típicamente *no* necesitarían interactuar con el API server de Kubernetes y para las cuales `automountServiceAccountToken: false` sería una buena práctica de seguridad?
<details>
  <summary>Haga clic para ver algunos ejemplos</summary>
  <p>
  Ejemplos incluyen:
  <ul>
    <li>Servidores web estáticos que solo sirven HTML/CSS/JS.</li>
    <li>Trabajos por lotes puramente computacionales que no consultan ni modifican el estado del clúster.</li>
    <li>Bases de datos a las que acceden las aplicaciones pero que no se gestionan a sí mismas a través de la API de K8s.</li>
    <li>Muchas aplicaciones simples que no necesitan descubrir otros servicios a través de la API ni gestionar otros recursos.</li>
  </ul>
  </p>
</details>

3.  **Usar una Service Account Dedicada con Permisos Mínimos:**
    *   Cree una ServiceAccount: `kubectl create serviceaccount my-app-sa`
    *   Cree un Role (por ejemplo, permitiendo solo ver pods en el namespace predeterminado):
        ```yaml
        # my-role.yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: default
          name: pod-viewer-role
        rules:
        - apiGroups: [""] # "" indica el grupo API principal
          resources: ["pods"]
          verbs: ["get", "watch", "list"]
        ```
        `kubectl apply -f my-role.yaml`
    *   Cree un RoleBinding:
        `kubectl create rolebinding pod-viewer-binding --role=pod-viewer-role --serviceaccount=default:my-app-sa`
    *   Despliegue un Pod usando esta ServiceAccount:
        ```yaml
        # sa-pod.yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: sa-pod
        spec:
          serviceAccountName: my-app-sa
          containers:
          - name: main
            image: appropriate/curl # Una imagen con curl
            command: ["sleep", "3600"] # Mantenerlo en ejecución para exec
        ```
        `kubectl apply -f sa-pod.yaml`
    *   Ejecute `exec` en `sa-pod` e intente usar su token para listar pods (esto requiere `curl` y `jq` en la imagen, o puede extraer el token y probar desde fuera):
        ```bash
        # kubectl exec -it sa-pod -- sh
        # TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
        # CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        # curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
        ```
    *   **Resultado Esperado:** El Pod debería poder listar pods usando su token. Si intentara otras acciones, serían denegadas.
    *   **Nota de Seguridad:** Siempre cree cuentas de servicio dedicadas con el menor privilegio necesario.

**Tarea de Desafío:**
1. ¿Qué comando `kubectl` usaría para listar todas las ServiceAccounts en el namespace `kube-system`?
2. Si tiene una ServiceAccount llamada `my-sa` en el namespace `my-ns`, ¿cómo podría (conceptualmente, o con `kubectl describe`) intentar averiguar a qué Roles o ClusterRoles está vinculada mediante RoleBindings o ClusterRoleBindings?
<details>
  <summary>Haga clic para ver soluciones/enfoques</summary>
  <p>
  1. Para listar ServiceAccounts en `kube-system`:
     ```bash
     kubectl get serviceaccounts -n kube-system
     # o
     kubectl get sa -n kube-system
     ```
  2. Para encontrar bindings para `my-sa` en `my-ns`:
     *   Listar todos los RoleBindings en `my-ns` y verificar su campo `subjects`:
         ```bash
         kubectl get rolebindings -n my-ns -o yaml 
         ```
         (Luego inspeccionar manualmente o usar `grep` para `my-sa`).
     *   Listar todos los ClusterRoleBindings y verificar su campo `subjects` (asegurándose de verificar si el namespace del sujeto coincide con `my-ns` si se especifica):
         ```bash
         kubectl get clusterrolebindings -o yaml
         ```
     *   `kubectl describe serviceaccount my-sa -n my-ns` a veces puede mostrar tokens, pero no directamente los roles a los que está vinculada. Verificar los bindings es más directo para los permisos.
  </p>
</details>

## Ejercicio 6: Perfiles de Seguridad del Entorno de Ejecución de Contenedores (Conceptual/Verificación)

**Objetivo:** Comprender cómo aplicar perfiles seccomp básicos.

**Instrucciones:**


**Punto de Predicción:** Seccomp (secure computing mode) es una característica del kernel de Linux que restringe las llamadas al sistema que un proceso puede realizar. ¿Por qué filtrar las llamadas al sistema es una medida de seguridad importante para los contenedores?
1.  **Desplegar un Pod con Perfil Seccomp `RuntimeDefault`:**
    *   Cree `seccomp-pod.yaml`:
        ```yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: seccomp-default-pod
        spec:
          securityContext:
            seccompProfile:
              type: RuntimeDefault
          containers:
          - name: main
            image: busybox
            command: ["sh", "-c", "echo 'Ejecutando con perfil seccomp RuntimeDefault'; sleep 3600"]
        ```
    *   Aplique: `kubectl apply -f seccomp-pod.yaml`
    *   Verifique el estado: `kubectl get pod seccomp-default-pod`
    *   **Resultado Esperado:** El Pod debería ejecutarse correctamente. El perfil `RuntimeDefault` es generalmente seguro y recomendado como base.
    *   **Nota de Seguridad:** `RuntimeDefault` usa el perfil seccomp definido por el entorno de ejecución de contenedores, que suele ser un buen punto de partida para el filtrado de llamadas al sistema. Para mayor seguridad, podrían necesitarse perfiles personalizados (más restrictivos).

**Punto de Verificación:**
El perfil seccomp `RuntimeDefault` es proporcionado por el entorno de ejecución de contenedores (por ejemplo, containerd, CRI-O). ¿Dónde podría buscar (conceptualmente) en un nodo o en la documentación del entorno de ejecución de contenedores para averiguar qué bloquea o permite realmente este perfil predeterminado?
<details>
  <summary>Haga clic para ver una pista</summary>
  <p>
  Normalmente necesitaría consultar la documentación de su entorno de ejecución de contenedores específico (como containerd o CRI-O). Algunos entornos de ejecución podrían exponer la ruta del perfil predeterminado en su configuración, o podría estar compilado. Para Docker, el perfil seccomp predeterminado está bien documentado y se puede encontrar en su código fuente o documentación.
  </p>
</details>

2.  **Discusión sobre AppArmor/SELinux (Conceptual):**
    *   **Verificación (Alto Nivel):**
        *   AppArmor: En un nodo, podría verificar `sudo aa-status` para ver los perfiles AppArmor cargados.
        *   SELinux: En un nodo, `getenforce` muestra el modo SELinux.
    *   **Interacción con Pods:** Kubernetes permite especificar perfiles AppArmor mediante anotaciones (`container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>`) u opciones SELinux en `securityContext.seLinuxOptions`.
    *   **Discusión:** ¿Por qué son importantes estos sistemas MAC? (Proporcionan una capa adicional de defensa al restringir lo que los procesos pueden hacer, incluso si se ejecutan como root o tienen algunas capabilities).
    *   **Nota de Seguridad:** Implementar y gestionar perfiles AppArmor/SELinux puede ser complejo pero ofrece un fortalecimiento robusto. Para KCSA, es importante comprender su propósito y cómo Kubernetes puede aprovecharlos.

**Tarea de Desafío:**
¿Cuál es una diferencia clave en lo que controla Seccomp versus lo que controlan AppArmor o SELinux (como sistemas de Control de Acceso Obligatorio - MAC)?
<details>
  <summary>Haga clic para ver la diferencia clave</summary>
  <p>
  Una diferencia clave es:
  <ul>
    <li><strong>Seccomp:</strong> Principalmente filtra <em>qué llamadas al sistema</em> puede realizar un proceso. Se trata de restringir la interacción del proceso con el kernel en la interfaz de llamadas al sistema.</li>
    <li><strong>AppArmor/SELinux (MAC):</strong> Controlan el <em>acceso a los recursos</em> (como archivos, puertos de red, capabilities) basándose en políticas y etiquetas definidas para sujetos (procesos) y objetos (recursos). Proporcionan un modelo de control de acceso más completo más allá del simple filtrado de llamadas al sistema.</li>
  </ul>
  A menudo se utilizan juntos para la defensa en profundidad.
  </p>
</details>

Estos ejercicios proporcionan un punto de partida para explorar la seguridad de los componentes del clúster de Kubernetes. Recuerde limpiar cualquier recurso que cree después de completar los laboratorios (por ejemplo, `kubectl delete pod test-pod`).

