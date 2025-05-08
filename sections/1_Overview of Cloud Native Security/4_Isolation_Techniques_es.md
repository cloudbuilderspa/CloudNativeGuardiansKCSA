---
layout: default
title: "Técnicas de Aislamiento"
parent: "1. Visión General de la Seguridad Cloud Native" 
nav_order: 4
permalink: /es/sections/vision-general-seguridad-cloud-native/tecnicas-aislamiento/
lang: es
---
# Técnicas de Aislamiento en Kubernetes

Un aislamiento efectivo es una piedra angular de la seguridad en Kubernetes, ayudando a limitar el radio de impacto de un posible compromiso. Las técnicas clave incluyen:

### Namespaces (Espacios de Nombres)
Los namespaces proporcionan un ámbito para los nombres y son una forma principal de dividir los recursos del clúster entre múltiples usuarios, equipos o aplicaciones. Permiten:
*   Aislar recursos: Los objetos en un namespace están ocultos para otros por defecto.
*   Limitar el alcance de los permisos: Los Roles RBAC tienen alcance de namespace, permitiendo un control de acceso detallado dentro de un namespace específico.
*   Aplicar cuotas de recursos: Se pueden definir ResourceQuotas por namespace para gestionar el consumo de recursos.

### Network Policies (Políticas de Red)
Las Network Policies controlan el flujo de tráfico a nivel de dirección IP o puerto (Capa 3 o Capa 4) entre Pods en un clúster. Son cruciales para:
*   Segmentar el tráfico de red: Definir qué Pods pueden comunicarse entre sí.
*   Implementar una postura de denegación por defecto: Bloquear todo el tráfico por defecto y luego permitir explícitamente solo las conexiones necesarias.
*   Limitar el movimiento lateral: Prevenir que un Pod comprometido ataque fácilmente a otros Pods o servicios en el clúster.

### Security Contexts (Contextos de Seguridad) de Pod y Pod Security Standards (PSS)
Estos mecanismos controlan la configuración de seguridad y los privilegios de los Pods y sus contenedores:
*   **Contextos de Seguridad:** Definidos en la especificación del Pod o Contenedor, controlan configuraciones como:
    *   `runAsUser` / `runAsGroup`: Ejecutar procesos como un ID de usuario/grupo específico.
    *   `runAsNonRoot`: Evitar que los contenedores se ejecuten como root.
    *   `readOnlyRootFilesystem`: Hacer inmutable el sistema de archivos raíz del contenedor.
    *   `allowPrivilegeEscalation`: Evitar que un proceso obtenga más privilegios que su padre.
    *   `capabilities`: Eliminar capabilities de Linux innecesarias.
    *   `seccompProfile`: Aplicar filtros seccomp para restringir las llamadas al sistema.
*   **Pod Security Standards (PSS) / Pod Security Admission (PSA):** Definen políticas de seguridad a nivel de clúster (`Privileged`, `Baseline`, `Restricted`) que son aplicadas a nivel de namespace por el controlador de Pod Security Admission. Esto asegura que los Pods se adhieran a mínimos de seguridad definidos.

Combinando estas técnicas de aislamiento, se puede mejorar significativamente la postura de seguridad de su clúster Kubernetes.
