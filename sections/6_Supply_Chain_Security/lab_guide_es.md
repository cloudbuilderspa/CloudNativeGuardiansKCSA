# Guía de Laboratorio: Seguridad de la Cadena de Suministro de Software

Esta guía de laboratorio proporciona ejercicios enfocados en comprender y analizar aspectos clave de la seguridad de la cadena de suministro de software en un contexto de Kubernetes. Los ejercicios son principalmente conceptuales y basados en la revisión, adecuados para un nivel de comprensión KCSA, utilizando ejemplos en lugar de requerir instalaciones complejas de herramientas.

**Nota:** Asegúrese de tener un editor de texto para revisar los ejemplos de manifiestos.

## Ejercicio 1: Análisis de Dockerfiles para Prácticas Seguras

**Objetivo:** Identificar prácticas seguras e inseguras en la creación de Dockerfiles.

**Instrucciones:**

1.  **Revisar un Ejemplo de Dockerfile Inseguro:**
    *   Considere el siguiente `Dockerfile.insecure`:
        ```dockerfile
        # Dockerfile.insecure
        FROM ubuntu:22.04 # Imagen base grande
        LABEL maintainer="test@example.com"

        # Instalar múltiples herramientas, algunas podrían no ser necesarias en producción
        RUN apt-get update && apt-get install -y \
            curl \
            git \
            python3 \
            python3-pip \
            vim \
            net-tools \
            && rm -rf /var/lib/apt/lists/*

        # Copiar todo el directorio de la aplicación (podría incluir .git, archivos temporales, etc.)
        COPY . /app
        WORKDIR /app

        # Instalar dependencias de Python
        RUN pip3 install -r requirements.txt

        # Exponer puerto y ejecutar aplicación como root (predeterminado)
        EXPOSE 8080
        CMD ["python3", "app.py"]
        ```
    *   **Identificar Posibles Problemas de Seguridad:**
        *   ¿Cuál es el riesgo de usar una imagen base grande como `ubuntu:22.04`?
        *   ¿Por qué la instalación de herramientas como `git`, `vim`, `net-tools` es potencialmente riesgosa en una imagen de producción?
        *   ¿Cuál es el problema con `COPY . /app`?
        *   ¿Cuál es el riesgo de ejecutar la aplicación como usuario root (predeterminado)?

2.  **Revisar un Ejemplo de Dockerfile Mejorado (Multi-Etapa):**
    *   Considere el siguiente `Dockerfile.improved`:
        ```dockerfile
        # Dockerfile.improved

        # ---- Etapa de Construcción (Build Stage) ----
        FROM python:3.9-slim as builder
        WORKDIR /app
        COPY requirements.txt .
        # Instalar solo dependencias de construcción, y hacerlo eficientemente
        RUN pip install --no-cache-dir --user -r requirements.txt

        COPY . .
        # (Imagine un paso de construcción aquí si fuera un lenguaje compilado)

        # ---- Etapa de Producción (Production Stage) ----
        FROM python:3.9-alpine # Imagen base mínima
        WORKDIR /app

        # Crear un usuario y grupo no root
        RUN addgroup -S appgroup && adduser -S appuser -G appgroup

        # Copiar solo los artefactos necesarios desde la etapa de construcción
        COPY --from=builder /app /app
        # O, más específicamente, si se usa el flag --user en pip install:
        # COPY --from=builder /root/.local /home/appuser/.local

        # Asegurar la propiedad correcta si es necesario y cambiar a usuario no root
        # RUN chown -R appuser:appgroup /app /home/appuser/.local (Ajustar ruta si es necesario)
        USER appuser

        EXPOSE 8080
        CMD ["python3", "app.py"]
        ```
    *   **Identificar Mejoras de Seguridad:**
        *   ¿Cómo mejora la seguridad el uso de `python:3.9-alpine` como base final?
        *   ¿Cuál es el beneficio de un build multi-etapa en este contexto?
        *   ¿Cómo mejora la seguridad la creación y uso de un usuario no root (`appuser`)?
        *   ¿Por qué `COPY --from=builder /app /app` (o rutas más específicas) es mejor que `COPY . /app` en la etapa de producción?

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   Siempre busque imágenes base mínimas (Alpine, distroless).
    *   Use builds multi-etapa para mantener las imágenes de producción ajustadas y libres de herramientas de construcción.
    *   Ejecute aplicaciones como usuarios no root.
    *   Sea explícito sobre los archivos copiados en la imagen; evite copiar archivos innecesarios (como directorios `.git`, archivos de configuración sensibles).

## Ejercicio 2: Interpretación de Resultados de Escaneo de Vulnerabilidades de Imágenes (Conceptual)

**Objetivo:** Comprender cómo interpretar la salida de un escáner de vulnerabilidades de imágenes.

**Instrucciones:**

1.  **Revisar Salida de Ejemplo de Escaneo de Vulnerabilidades:**
    *   Imagine que ha escaneado una imagen antigua, `nginx:1.18-alpine`, usando una herramienta como Trivy. Aquí hay un fragmento de salida simplificado e hipotético:
        ```
        nginx:1.18-alpine (alpine 3.12.0)
        ==================================
        Total: 5 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 1, CRITICAL: 1)

        CRITICAL: CVE-2021-XXXX - libcrypto1.1 - Vulnerabilidad no especificada
        Severity: CRITICAL
        Installed Version: 1.1.1g-r0
        Fixed Version: 1.1.1k-r0
        Description: ...

        HIGH: CVE-2020-YYYY - nginx - HTTP Request Smuggling
        Severity: HIGH
        Installed Version: 1.18.0
        Fixed Version: 1.19.0
        Description: ...

        MEDIUM: CVE-2019-ZZZZ - zlib - Lectura fuera de límites
        Severity: MEDIUM
        Installed Version: 1.2.11-r1
        Fixed Version: 1.2.11-r3
        Description: ...
        ```

2.  **Análisis y Discusión:**
    *   Identifique las vulnerabilidades de severidad CRITICAL y HIGH.
    *   Para `CVE-2021-XXXX` en `libcrypto1.1`, ¿cuál es la versión instalada y cuál es la versión corregida?
    *   ¿Qué acciones debería tomar una organización al ver este resultado de escaneo?
        *   Actualizar `libcrypto1.1` a `1.1.1k-r0` (probablemente actualizando la versión de la imagen base de Alpine).
        *   Actualizar `nginx` a `1.19.0` o posterior.
        *   Reconstruir la imagen de la aplicación con estos componentes actualizados.
        *   Considerar bloquear el despliegue si las vulnerabilidades críticas no pueden remediarse inmediatamente.
    *   ¿Por qué es importante escanear no solo las dependencias directas sino también los paquetes del SO en la imagen base?

3.  **Notas de Seguridad y Conclusiones KCSA:**
    *   El escaneo de imágenes es esencial para identificar vulnerabilidades conocidas.
    *   Concéntrese primero en remediar las vulnerabilidades CRITICAL y HIGH.
    *   El escaneo debe integrarse en los pipelines de CI/CD y en los registros.
    *   Comprenda que "Fixed Version" indica que hay un parche disponible.

## Ejercicio 3: Comprensión de la Firma de Imágenes y el Control de Admisión (Conceptual)

**Objetivo:** Comprender el concepto de firma de imágenes y cómo los controladores de admisión pueden aplicar políticas basadas en firmas.

**Instrucciones (Revisión Conceptual):**

1.  **Flujo de Firma de Imágenes (Conceptual):**
    *   **Pipeline CI/CD:** Después de construir y probar una imagen, se utiliza una herramienta como `Cosign` (de Sigstore) para firmar la imagen.
    *   **Almacenamiento de Firmas:** La firma puede almacenarse en el registro OCI junto con la imagen o en un registro de transparencia como Rekor.
    *   **Gestión de Claves:** La clave privada utilizada para firmar debe gestionarse de forma segura. La firma sin clave (usando identidades OIDC) es una opción con Sigstore.

2.  **Control de Admisión para Verificación de Firmas (Ejemplo Conceptual):**
    *   Revise un fragmento simplificado de manifiesto de política Kyverno (no aplicar):
        ```yaml
        # kyverno-policy-example.yaml
        apiVersion: kyverno.io/v1
        kind: ClusterPolicy
        metadata:
          name: check-image-signatures
        spec:
          validationFailureAction: Enforce # Bloquear despliegue si falla
          rules:
          - name: verify-image-signature
            match:
              resources:
                kinds:
                - Pod
            verifyImages:
            - image: "*" # Aplicar a todas las imágenes
              key: | # Clave pública del firmante confiable
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                -----END PUBLIC KEY-----
              # O usar otras atestaciones como sin clave con emisor/sujeto específico
        ```
    *   **Discusión:**
        *   ¿Cuál es el rol de esta `ClusterPolicy` de Kyverno? (Verificar las firmas de las imágenes antes de permitir el despliegue del Pod).
        *   ¿Qué sucede si se despliega una imagen sin firmar o una imagen firmada por una clave no confiable? (El despliegue se bloquea debido a `validationFailureAction: Enforce`).
        *   ¿De dónde proviene la clave pública para la verificación? (Está configurada en la política y debe corresponder a la clave privada utilizada para firmar en CI/CD).
    *   **Nota de Seguridad:** La firma de imágenes y el control de admisión proporcionan fuertes garantías de que solo se ejecutan imágenes confiables y verificadas en su clúster.

## Ejercicio 4: Revisión de un Ejemplo de Lista de Materiales de Software (SBOM)

**Objetivo:** Comprender la estructura y utilidad de un SBOM.

**Instrucciones (Revisión Conceptual):**

1.  **Revisar un Fragmento de un SBOM (ejemplo CycloneDX JSON):**
    ```json
    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version": 1,
      "metadata": {
        "timestamp": "2023-10-27T12:00:00Z",
        "tools": [ { "vendor": "Trivy", "name": "Trivy", "version": "0.45.0" } ],
        "component": {
          "type": "application",
          "name": "my-web-app",
          "version": "1.2.3"
        }
      },
      "components": [
        {
          "type": "library",
          "name": "requests",
          "version": "2.28.1",
          "purl": "pkg:pypi/requests@2.28.1"
        },
        {
          "type": "library",
          "name": "urllib3",
          "version": "1.26.12",
          "purl": "pkg:pypi/urllib3@1.26.12",
          "scope": "required" // Esta es una dependencia transitiva de 'requests'
        },
        {
          "type": "operating-system",
          "name": "alpine",
          "version": "3.18.0"
        }
      ]
    }
    ```
2.  **Análisis y Discusión:**
    *   Identifique una dependencia directa de `my-web-app`. (por ejemplo, `requests`)
    *   Identifique una dependencia transitiva. (por ejemplo, `urllib3` es una dependencia de `requests`)
    *   Si se anuncia un nuevo CVE para `urllib3` versión `1.26.12`, ¿cómo ayudaría este SBOM a evaluar rápidamente el impacto? (Permite ver rápidamente que `my-web-app` está afectado porque usa `requests` que a su vez usa el `urllib3` vulnerable).
    *   ¿Qué otra información está presente (herramienta utilizada, marca de tiempo, SO)?
    *   **Nota de Seguridad:** Los SBOMs proporcionan transparencia sobre los componentes de software, ayudando en la gestión de vulnerabilidades, cumplimiento de licencias y comprensión de los riesgos de la cadena de suministro.

## Ejercicio 5: Prácticas Seguras de CI/CD (Discusión Conceptual)

**Objetivo:** Discutir las mejores prácticas de seguridad para pipelines CI/CD involucrados en la construcción y despliegue en Kubernetes.

**Instrucciones (Puntos de Discusión):**

1.  **Escenario:** Un pipeline CI/CD (por ejemplo, GitHub Actions, Jenkins, GitLab CI) es responsable de:
    *   Obtener código de un repositorio Git.
    *   Construir una imagen de contenedor.
    *   Subir la imagen a un registro de contenedores privado.
    *   Desplegar la aplicación (actualizando un Deployment) en un clúster de Kubernetes.

2.  **Puntos de Discusión:**
    *   **Credenciales del Registro:**
        *   ¿Cómo debería autenticarse el pipeline en el registro de contenedores privado para subir la imagen? (por ejemplo, usando tokens de corta duración, credenciales de cuenta de servicio para el sistema CI/CD, gestión de secretos incorporada de la plataforma como secretos de GitHub Actions).
        *   ¿Por qué estas credenciales *no* deberían estar codificadas (hardcoded) en el script del pipeline?
    *   **Credenciales de Despliegue de Kubernetes:**
        *   Si el pipeline despliega en Kubernetes, ¿qué tipo de ServiceAccount debería usar en el clúster? (Una SA dedicada con el menor privilegio, con alcance al namespace objetivo, y solo con permisos para actualizar los Deployments/Services específicos que gestiona).
        *   ¿Cómo pueden herramientas como `kubectl auth can-i --as=system:serviceaccount:<ns>:<sa>` ayudar a verificar estos permisos mínimos?
    *   **Asegurando el Código Antes de CI:**
        *   ¿Cómo contribuyen las reglas de protección de ramas en Git (por ejemplo, requerir revisiones, pasar verificaciones de estado) a la seguridad de la cadena de suministro antes de que el código llegue al pipeline de CI? (Prevenir subidas directas de código potencialmente malicioso o no probado a las ramas principales).
    *   **Integridad del Pipeline:** ¿Cómo protegería la definición del propio pipeline (por ejemplo, `Jenkinsfile`, `.github/workflows/`) de modificaciones no autorizadas? (Revisiones de código, protección de ramas en el repositorio SCM que almacena estos archivos).
    *   **Nota de Seguridad:** Los pipelines CI/CD son infraestructura crítica y un objetivo principal. Asegurarlos con el menor privilegio, gestión de secretos y verificaciones de integridad es vital.

## Ejercicio 6: Análisis de la Configuración de un Repositorio de Artefactos (Conceptual)

**Objetivo:** Considerar las configuraciones de seguridad para un repositorio de artefactos (imágenes).

**Instrucciones (Puntos de Discusión):**

1.  **Escenario:** Una organización utiliza un repositorio de imágenes privado (por ejemplo, Harbor, Artifactory, AWS ECR, GCP Artifact Registry).

2.  **Puntos de Discusión:**
    *   **Controles de Acceso:**
        *   ¿Qué tipos de usuarios o sistemas necesitarían subir imágenes? (Sistemas CI/CD, desarrolladores en casos específicos).
        *   ¿Qué tipos de usuarios o sistemas necesitarían bajar imágenes? (Nodos/Kubelets de Kubernetes, desarrolladores, otros trabajos CI/CD).
        *   ¿Cómo puede implementar el menor privilegio para estas acciones? (por ejemplo, cuentas de usuario específicas o cuentas robot con permisos de subida/bajada con alcance a rutas de repositorio o proyectos particulares).
    *   **Escaneo de Vulnerabilidades dentro del Repositorio:**
        *   ¿Por qué es beneficioso que el propio repositorio admita o se integre con escáneres de vulnerabilidades? (Puede re-escanear imágenes periódicamente a medida que se encuentran nuevos CVEs, puede proporcionar un panel central de vulnerabilidades en todas las imágenes almacenadas).
    *   **Políticas de Retención y Limpieza de Imágenes:**
        *   ¿Cuáles son los beneficios de tener políticas para eliminar imágenes antiguas, no utilizadas o altamente vulnerables? (Reduce los costos de almacenamiento, reduce el riesgo de desplegar por error software con vulnerabilidades conocidas).
    *   **Replicación y Proxy:**
        *   Si el repositorio replica imágenes a otras regiones/registros, ¿cómo debe asegurarse esto? (Canales seguros, verificaciones de integridad).
        *   Si el repositorio actúa como una caché de paso (pull-through cache) para registros públicos (como Docker Hub), ¿qué políticas deberían existir? (por ejemplo, solo almacenar en caché/hacer proxy de imágenes oficiales, escanear imágenes obtenidas por proxy).
    *   **Nota de Seguridad:** Un repositorio de artefactos bien asegurado es un punto de control clave en la cadena de suministro de software.

Estos ejercicios conceptuales deberían ayudar a consolidar su comprensión de las diferentes facetas de la seguridad de la cadena de suministro de software relevantes para KCSA.

