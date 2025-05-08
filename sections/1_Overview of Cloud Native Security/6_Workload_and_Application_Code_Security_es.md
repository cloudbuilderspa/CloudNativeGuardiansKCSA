---
layout: default
title: "Seguridad de Cargas de Trabajo y Código de Aplicación"
parent: "1. Visión General de la Seguridad Cloud Native" 
nav_order: 6
permalink: /es/sections/vision-general-seguridad-cloud-native/seguridad-cargas-trabajo-codigo-app/
lang: es
---
# Seguridad de Cargas de Trabajo y Código de Aplicación

Asegurar las cargas de trabajo y el código de aplicación que ejecutan implica varias prácticas clave:

*   **Prácticas de Codificación Segura:** Implementación de prácticas de codificación segura para prevenir vulnerabilidades en el propio código de la aplicación. Esto incluye la validación de entradas, el manejo adecuado de errores y evitar errores comunes como los listados en el OWASP Top 10.
*   **Gestión de Secretos:** Uso de Kubernetes Secrets para almacenar y gestionar de forma segura información sensible como contraseñas, claves API y tokens, en lugar de codificarlos directamente en el código de la aplicación o en las imágenes de contenedor.
*   **Escaneo de Vulnerabilidades:** Realización de escaneos regulares de las aplicaciones, sus dependencias y las propias cargas de trabajo para identificar y mitigar posibles vulnerabilidades. Esto debería ser parte del pipeline de CI/CD y de la monitorización continua.
