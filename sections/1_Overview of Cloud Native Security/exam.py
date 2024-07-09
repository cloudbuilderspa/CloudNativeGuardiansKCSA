import random

class Pregunta:
    def __init__(self, enunciado, opciones, respuesta_correcta):
        self.enunciado = enunciado
        self.opciones = opciones
        self.respuesta_correcta = respuesta_correcta

    def mostrar_pregunta(self):
        print(self.enunciado)
        for i, opcion in enumerate(self.opciones):
            print(f"{i+1}. {opcion}")
        print()  # Añadir un salto de línea después de las opciones

    def verificar_respuesta(self, respuesta):
        return respuesta == self.respuesta_correcta

# Preguntas en inglés
preguntas_ingles = [
    Pregunta("What is the first step to ensure security in software development?",
             ["Input validation", "Dependency management", "Security testing", "Risk analysis"],
             1),
    Pregunta("Which aspect does container image security cover?",
             ["Node configuration", "Permission management", "Vulnerability detection", "Image scanning"],
             4),
    Pregunta("What does cloud infrastructure security involve?",
             ["Secure configurations", "Compliance with security standards", "Security testing", "Log monitoring"],
             2),
    Pregunta("What is a best practice to protect a REST API?",
             ["Authentication and authorization", "Data encryption", "Input validation", "Vulnerability scanning"],
             1),
    Pregunta("What is a common technique to prevent SQL injection attacks?",
             ["Using parameterized queries", "Data encryption", "Packet filtering", "Port scanning"],
             1),
    Pregunta("What is included in the 4Cs of Cloud Native Security?",
             ["Code, Container, Cluster, Cloud", "Code, Configuration, Cluster, Cloud", "Code, Container, Configuration, Cloud", "Code, Container, Cluster, Connectivity"],
             1),
    Pregunta("Which practice is crucial for maintaining secure container images?",
             ["Regular updates", "Dependency management", "Risk analysis", "Secure configurations"],
             1),
    Pregunta("What is the main focus of cluster security in Kubernetes?",
             ["Node configuration and permission management", "Container scanning", "Input validation", "Log monitoring"],
             1),
    Pregunta("Which of the following is a key aspect of cloud provider security?",
             ["Secure service configurations", "Data encryption", "Network monitoring", "Input validation"],
             1),
    Pregunta("What does the use of TLS ensure in a Kubernetes cluster?",
             ["Encrypted communications", "Secure container images", "Proper node configurations", "Secure input validation"],
             1),
    Pregunta("Which method controls access to cluster resources?",
             ["Authentication and authorization", "Network monitoring", "Regular updates", "Secure configurations"],
             1),
    Pregunta("What is implemented to guide secure cluster configuration?",
             ["Security frameworks like CIS Benchmarks and NIST", "Dependency management", "Risk analysis", "Packet filtering"],
             1),
    Pregunta("Which Kubernetes feature isolates resources within the cluster?",
             ["Namespaces", "Pod Security Policies", "Network Policies", "Secrets Management"],
             1),
    Pregunta("What is the purpose of Network Policies in Kubernetes?",
             ["Control network traffic between Pods", "Secure container images", "Manage dependencies", "Validate inputs"],
             1),
    Pregunta("What is a Security Context used for in Kubernetes?",
             ["Define permissions and restrictions on containers", "Encrypt communications", "Manage dependencies", "Monitor logs"],
             1),
    Pregunta("Why is it important to regularly scan container images?",
             ["To detect vulnerabilities", "To manage dependencies", "To encrypt data", "To monitor network traffic"],
             1),
    Pregunta("What is the benefit of using digital signatures for container images?",
             ["Ensure integrity and authenticity", "Encrypt communications", "Manage permissions", "Monitor logs"],
             1),
    Pregunta("Which practice helps to securely store and manage sensitive information?",
             ["Use of Kubernetes Secrets", "Regular updates", "Network monitoring", "Input validation"],
             1),
    Pregunta("Why are Pod Security Policies important in Kubernetes?",
             ["To define security conditions for Pods", "To encrypt communications", "To manage dependencies", "To monitor logs"],
             1),
    Pregunta("What should be implemented to ensure secure development practices?",
             ["Secure coding practices", "Data encryption", "Log monitoring", "Packet filtering"],
             1),
    Pregunta("What is the role of IAM in cloud provider security?",
             ["Manage identities and access", "Encrypt data", "Monitor network traffic", "Validate inputs"],
             1),
    Pregunta("What is the main purpose of using TLS in Kubernetes?",
             ["Encrypt communications within the cluster", "Secure container images", "Manage dependencies", "Monitor logs"],
             1),
    Pregunta("How can namespaces enhance security in a Kubernetes cluster?",
             ["By isolating resources and limiting permissions", "By encrypting data", "By monitoring logs", "By managing dependencies"],
             1),
    Pregunta("What is a key aspect of artifact repository security?",
             ["Regular scanning for vulnerabilities", "Managing permissions", "Encrypting communications", "Monitoring network traffic"],
             1),
    Pregunta("Why is compliance with CIS Benchmarks important in Kubernetes?",
             ["To guide secure cluster configuration", "To encrypt data", "To manage dependencies", "To monitor logs"],
             1),
    Pregunta("What should be used to define permissions and restrictions on containers?",
             ["Security Contexts", "Data encryption", "Dependency management", "Log monitoring"],
             1),
    Pregunta("What is the role of regular vulnerability scanning in Kubernetes?",
             ["To identify and mitigate potential vulnerabilities", "To encrypt data", "To manage permissions", "To monitor network traffic"],
             1),
    Pregunta("What practice helps to ensure the integrity of container images before deployment?",
             ["Use of digital signatures", "Data encryption", "Log monitoring", "Packet filtering"],
             1),
    Pregunta("Why are Pod Security Policies (PSP) crucial in Kubernetes?",
             ["To control the security configurations of Pods", "To encrypt communications", "To manage dependencies", "To monitor logs"],
             1),
    Pregunta("What is an essential part of cloud provider security in Kubernetes?",
             ["Secure configuration of services", "Encrypting data", "Monitoring logs", "Validating inputs"],
             1)
]

# Preguntas en español
preguntas_espanol = [
    Pregunta("¿Cuál es el primer paso para garantizar la seguridad en el desarrollo de software?",
             ["Validación de entradas", "Gestión de dependencias", "Pruebas de seguridad", "Análisis de riesgos"],
             1),
    Pregunta("¿Qué aspecto abarca la seguridad de las imágenes de contenedor?",
             ["Configuración de nodos", "Gestión de permisos", "Detección de vulnerabilidades", "Escaneo de imágenes"],
             4),
    Pregunta("¿Qué implica la seguridad de la infraestructura en la nube?",
             ["Configuraciones seguras", "Cumplimiento de estándares de seguridad", "Pruebas de seguridad", "Monitorización de logs"],
             2),
    Pregunta("¿Cuál es una buena práctica para proteger una API REST?",
             ["Autenticación y autorización", "Encriptación de datos", "Validación de entradas", "Escaneo de vulnerabilidades"],
             1),
    Pregunta("¿Qué es una técnica común para prevenir ataques de inyección de SQL?",
             ["Uso de consultas parametrizadas", "Cifrado de datos", "Filtrado de paquetes", "Escaneo de puertos"],
             1),
    Pregunta("¿Qué incluye los 4Cs de la seguridad nativa de la nube?",
             ["Código, Contenedor, Clúster, Nube", "Código, Configuración, Clúster, Nube", "Código, Contenedor, Configuración, Nube", "Código, Contenedor, Clúster, Conectividad"],
             1),
    Pregunta("¿Qué práctica es crucial para mantener imágenes de contenedores seguras?",
             ["Actualizaciones regulares", "Gestión de dependencias", "Análisis de riesgos", "Configuraciones seguras"],
             1),
    Pregunta("¿Cuál es el enfoque principal de la seguridad del clúster en Kubernetes?",
             ["Configuración de nodos y gestión de permisos", "Escaneo de contenedores", "Validación de entradas", "Monitorización de logs"],
             1),
    Pregunta("¿Cuál de los siguientes es un aspecto clave de la seguridad del proveedor de la nube?",
             ["Configuraciones seguras de servicios", "Cifrado de datos", "Monitorización de la red", "Validación de entradas"],
             1),
    Pregunta("¿Qué garantiza el uso de TLS en un clúster de Kubernetes?",
             ["Comunicaciones cifradas", "Imágenes de contenedores seguras", "Configuraciones correctas de nodos", "Validación segura de entradas"],
             1),
    Pregunta("¿Qué método controla el acceso a los recursos del clúster?",
             ["Autenticación y autorización", "Monitorización de la red", "Actualizaciones regulares", "Configuraciones seguras"],
             1),
    Pregunta("¿Qué se implementa para guiar la configuración segura del clúster?",
             ["Marcos de seguridad como CIS Benchmarks y NIST", "Gestión de dependencias", "Análisis de riesgos", "Filtrado de paquetes"],
             1),
    Pregunta("¿Qué característica de Kubernetes aísla los recursos dentro del clúster?",
             ["Namespaces", "Políticas de Seguridad de Pods", "Políticas de Red", "Gestión de Secretos"],
             1),
    Pregunta("¿Cuál es el propósito de las Políticas de Red en Kubernetes?",
             ["Controlar el tráfico de red entre Pods", "Asegurar imágenes de contenedores", "Gestionar dependencias", "Validar entradas"],
             1),
    Pregunta("¿Para qué se utiliza un Security Context en Kubernetes?",
             ["Definir permisos y restricciones en los contenedores", "Cifrar comunicaciones", "Gestionar dependencias", "Monitorizar logs"],
             1),
    Pregunta("¿Por qué es importante escanear regularmente las imágenes de contenedores?",
             ["Para detectar vulnerabilidades", "Para gestionar dependencias", "Para cifrar datos", "Para monitorizar el tráfico de la red"],
             1),
    Pregunta("¿Cuál es el beneficio de usar firmas digitales en las imágenes de contenedores?",
             ["Garantizar la integridad y autenticidad", "Cifrar comunicaciones", "Gestionar permisos", "Monitorizar logs"],
             1),
    Pregunta("¿Qué práctica ayuda a almacenar y gestionar información sensible de manera segura?",
             ["Uso de Kubernetes Secrets", "Actualizaciones regulares", "Monitorización de la red", "Validación de entradas"],
             1),
    Pregunta("¿Por qué son importantes las Políticas de Seguridad de Pods en Kubernetes?",
             ["Para definir condiciones de seguridad para los Pods", "Para cifrar comunicaciones", "Para gestionar dependencias", "Para monitorizar logs"],
             1),
    Pregunta("¿Qué se debe implementar para asegurar prácticas de desarrollo seguro?",
             ["Prácticas de codificación segura", "Cifrado de datos", "Monitorización de logs", "Filtrado de paquetes"],
             1),
    Pregunta("¿Cuál es el papel de IAM en la seguridad del proveedor de la nube?",
             ["Gestionar identidades y accesos", "Cifrar datos", "Monitorizar el tráfico de la red", "Validar entradas"],
             1),
    Pregunta("¿Cuál es el propósito principal del uso de TLS en Kubernetes?",
             ["Cifrar comunicaciones dentro del clúster", "Asegurar imágenes de contenedores", "Gestionar dependencias", "Monitorizar logs"],
             1),
    Pregunta("¿Cómo pueden los namespaces mejorar la seguridad en un clúster de Kubernetes?",
             ["Aislando recursos y limitando permisos", "Cifrando datos", "Monitorizando logs", "Gestionando dependencias"],
             1),
    Pregunta("¿Cuál es un aspecto clave de la seguridad del repositorio de artefactos?",
             ["Escaneo regular de vulnerabilidades", "Gestión de permisos", "Cifrado de comunicaciones", "Monitorización del tráfico de la red"],
             1),
    Pregunta("¿Por qué es importante cumplir con los CIS Benchmarks en Kubernetes?",
             ["Para guiar la configuración segura del clúster", "Para cifrar datos", "Para gestionar dependencias", "Para monitorizar logs"],
             1),
    Pregunta("¿Qué se debe usar para definir permisos y restricciones en los contenedores?",
             ["Security Contexts", "Cifrado de datos", "Gestión de dependencias", "Monitorización de logs"],
             1),
    Pregunta("¿Cuál es el papel del escaneo regular de vulnerabilidades en Kubernetes?",
             ["Identificar y mitigar posibles vulnerabilidades", "Cifrar datos", "Gestionar permisos", "Monitorizar el tráfico de la red"],
             1),
    Pregunta("¿Qué práctica ayuda a asegurar la integridad de las imágenes de contenedores antes del despliegue?",
             ["Uso de firmas digitales", "Cifrado de datos", "Monitorización de logs", "Filtrado de paquetes"],
             1),
    Pregunta("¿Por qué son cruciales las Políticas de Seguridad de Pods (PSP) en Kubernetes?",
             ["Para controlar las configuraciones de seguridad de los Pods", "Para cifrar comunicaciones", "Para gestionar dependencias", "Para monitorizar logs"],
             1),
    Pregunta("¿Cuál es una parte esencial de la seguridad del proveedor de la nube en Kubernetes?",
             ["Configuración segura de los servicios", "Cifrado de datos", "Monitorización de logs", "Validación de entradas"],
             1)
]

# Solicitar al usuario que elija el idioma
idioma = input("Elige el idioma para estudiar (inglés/español): ").strip().lower()
print()  # Añadir un salto de línea después de la selección del idioma

if idioma == "ingles" or idioma == "inglés":
    preguntas = preguntas_ingles
    idioma_seleccionado = "Inglés"
elif idioma == "espanol" or idioma == "español":
    preguntas = preguntas_espanol
    idioma_seleccionado = "Español"
else:
    print("Idioma no reconocido, se usará inglés por defecto.")
    preguntas = preguntas_ingles
    idioma_seleccionado = "Inglés"

# Mezclar las preguntas para mayor aleatoriedad
random.shuffle(preguntas)

puntaje = 0

for pregunta in preguntas:
    pregunta.mostrar_pregunta()
    respuesta = int(input("Ingrese el número de la opción correcta: "))
    if pregunta.verificar_respuesta(respuesta):
        puntaje += 1
    print()  # Añadir un salto de línea después de cada pregunta

print(f"Tu puntaje final es: {puntaje}/{len(preguntas)} en {idioma_seleccionado}")

