# Repositorio de Estudio para la Certificación KCSA (CloudNativeGuardiansKCSA)

## Propósito

Bienvenido al repositorio de CloudNativeGuardiansKCSA. Este espacio está diseñado para servir como una guía de estudio completa y una plataforma de autoevaluación para prepararte para la certificación **KCSA (Kubernetes and Cloud Native Security Associate)**. Aquí encontrarás materiales de estudio, ejemplos prácticos y exámenes por sección para ayudarte a dominar los conceptos clave de la seguridad nativa de la nube.

## Estructura del Repositorio

El contenido de este repositorio está organizado en secciones temáticas, cada una cubriendo un dominio específico del examen KCSA. Todas las secciones se encuentran dentro del directorio `sections/`.

### Secciones Principales:

1.  **`1_Overview of Cloud Native Security`**: Introducción a los conceptos fundamentales de la seguridad en entornos nativos de la nube, incluyendo los 4Cs, seguridad del proveedor de la nube, frameworks de control y más.
2.  **`2_Cluster_Setup`**: Configuración segura de clústeres de Kubernetes.
3.  **`3_Cluster_Hardening`**: Técnicas y mejores prácticas para fortalecer la seguridad de los clústeres de Kubernetes.
4.  **`4_System_Hardening`**: Fortalecimiento de la seguridad a nivel de sistema operativo y nodos del clúster.
5.  **`5_Minimize_Microservice_Vulnerabilities`**: Estrategias para reducir las vulnerabilidades en microservicios.
6.  **`6_Supply_Chain_Security`**: Aseguramiento de la cadena de suministro de software, desde el código hasta el despliegue.
7.  **`7_Monitoring_Logging_and_Runtime_Security`**: Monitorización, registro y seguridad en tiempo de ejecución para aplicaciones nativas de la nube.

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

# CloudNativeGuardiansKCSA
"Comprehensive resources and study materials for the Kubernetes Cloud Native Security Associate (KCSA) exam. This repository includes detailed guides, best practices, and hands-on examples to help you master Kubernetes security."
