Para la versión en inglés, por favor vea [README.md](README.md).
---

# Repositorio de Estudio para la Certificación KCSA (CloudNativeGuardiansKCSA)

## Propósito

Bienvenido al repositorio de CloudNativeGuardiansKCSA. Este espacio está diseñado para servir como una guía de estudio completa y una plataforma de autoevaluación para prepararte para la certificación **KCSA (Kubernetes and Cloud Native Security Associate)**. Aquí encontrarás materiales de estudio, ejemplos prácticos y exámenes por sección para ayudarte a dominar los conceptos clave de la seguridad nativa de la nube.

## Estructura del Repositorio

El contenido de este repositorio está organizado en secciones temáticas, cada una cubriendo un dominio específico del examen KCSA. Todas las secciones se encuentran dentro del directorio `sections/`.

### Secciones Principales:

1.  **[1. Visión General de la Seguridad Cloud Native](/CloudNativeGuardiansKCSA/es/sections/vision-general-seguridad-cloud-native/)**
    *   ([1. Overview of Cloud Native Security](/CloudNativeGuardiansKCSA/sections/overview-cloud-native-security/))
2.  **[2. Configuración del Clúster](/CloudNativeGuardiansKCSA/es/sections/configuracion-cluster/)**
    *   ([2. Cluster Setup](/CloudNativeGuardiansKCSA/sections/cluster-setup/))
3.  **[3. Fortalecimiento del Clúster](/CloudNativeGuardiansKCSA/es/sections/fortalecimiento-cluster/)**
    *   ([3. Cluster Hardening](/CloudNativeGuardiansKCSA/sections/cluster-hardening/))
4.  **[4. Fortalecimiento del Sistema (Modelo de Amenaza)](/CloudNativeGuardiansKCSA/es/sections/fortalecimiento-sistema/)**
    *   ([4. System Hardening (Threat Model)](/CloudNativeGuardiansKCSA/sections/system-hardening/))
5.  **[5. Minimizar Vulnerabilidades de Microservicios](/CloudNativeGuardiansKCSA/es/sections/minimizar-vulnerabilidades-microservicios/)**
    *   ([5. Minimize Microservice Vulnerabilities](/CloudNativeGuardiansKCSA/sections/minimize-microservice-vulnerabilities/))
6.  **[6. Seguridad de la Cadena de Suministro](/CloudNativeGuardiansKCSA/es/sections/seguridad-cadena-suministro/)**
    *   ([6. Supply Chain Security](/CloudNativeGuardiansKCSA/sections/supply-chain-security/))
7.  **[7. Monitorización, Logging y Seguridad en Runtime](/CloudNativeGuardiansKCSA/es/sections/monitorizacion-logging-runtime-seguridad/)**
    *   ([7. Monitoring, Logging & Runtime Security](/CloudNativeGuardiansKCSA/sections/monitoring-logging-runtime-security/))

### Organización del Contenido Bilingüe:

Para facilitar el estudio a una audiencia más amplia, el material de estudio dentro de cada sección está disponible en dos idiomas:

*   **Español:** Los archivos de contenido en español tienen el sufijo `_es.md` (por ejemplo, `main_concepts_es.md`).
*   **Inglés:** Los archivos de contenido en inglés tienen el sufijo `_en.md` (por ejemplo, `main_concepts_en.md`).

Cada sección también puede incluir:
*   Archivos de laboratorio (por ejemplo, `lab_ejemplo.yml` o específicos como `lab_np.yml` y `lab_pss.yml` en la sección 1) para practicar los conceptos aprendidos.
*   Un script de examen interactivo `exam.py`.

## Cómo Usar los Exámenes de Práctica

Cada sección temática incluye un script de Python (`exam.py`) que te permite realizar un examen de práctica para evaluar tus conocimientos sobre los temas de esa sección.

Para ejecutar un examen:

1.  **Navega al directorio de la sección deseada:**
    ```bash
    cd sections/NOMBRE_DE_LA_SECCION/
    # Ejemplo:
    # cd sections/1_Overview of Cloud Native Security/
    ```

2.  **Ejecuta el script de examen:**
    Utiliza `python` o `python3` dependiendo de tu configuración de sistema.
    ```bash
    python exam.py
    # o
    # python3 exam.py
    ```

3.  **Selecciona el Idioma:**
    Al inicio, el script te pedirá que elijas el idioma para el examen. Puedes ingresar:
    *   `en` para Inglés.
    *   `es` para Español.

Sigue las instrucciones en pantalla para completar el examen. Al finalizar, recibirás tu puntaje.

## Contribuciones

¡Las contribuciones son bienvenidas! Si encuentras errores, tienes sugerencias para mejorar el material, quieres añadir nuevas preguntas a los exámenes, o proponer contenido adicional, por favor, siéntete libre de:

*   Abrir un **Issue** para discutir los cambios.
*   Enviar un **Pull Request** con tus mejoras.

Juntos podemos hacer de este repositorio un recurso aún mejor para la comunidad.
