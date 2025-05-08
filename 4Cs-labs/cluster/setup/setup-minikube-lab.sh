#!/bin/bash

# =========================================================================
# setup-minikube-lab.sh
# =========================================================================
# Descripción: Script para configurar un laboratorio de Kubernetes con Minikube
#              e implementar ejemplos de Pod Security Standards
# Autor: Cloud Native Guardians
# Fecha: 2025-05-08
# =========================================================================

# Colores para mejorar la salida
ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[0;33m'
AZUL='\033[0;34m'
NC='\033[0m' # Sin Color

# Función para mostrar mensajes con formato
mostrar_mensaje() {
  local tipo=$1
  local mensaje=$2
  local prefijo=""
  local color=$NC
  
  case $tipo in
    "info")
      prefijo="[INFO]"
      color=$AZUL
      ;;
    "exito")
      prefijo="[ÉXITO]"
      color=$VERDE
      ;;
    "alerta")
      prefijo="[ALERTA]"
      color=$AMARILLO
      ;;
    "error")
      prefijo="[ERROR]"
      color=$ROJO
      ;;
    *)
      prefijo="[LOG]"
      ;;
  esac
  
  echo -e "${color}${prefijo} ${mensaje}${NC}"
}

# Función para manejar errores
manejar_error() {
  local mensaje=$1
  local codigo_salida=${2:-1}
  
  mostrar_mensaje "error" "$mensaje"
  exit $codigo_salida
}

# Función para verificar si un comando existe
verificar_comando() {
  local comando=$1
  local mensaje_instalacion=$2
  
  if ! command -v $comando &> /dev/null; then
    mostrar_mensaje "alerta" "No se encontró: $comando"
    if [ -n "$mensaje_instalacion" ]; then
      mostrar_mensaje "info" "$mensaje_instalacion"
    fi
    return 1
  else
    mostrar_mensaje "info" "Encontrado: $comando $(command -v $comando)"
    return 0
  fi
}

# Función para verificar requisitos
verificar_requisitos() {
  mostrar_mensaje "info" "Verificando requisitos del sistema..."
  
  # Verificar Homebrew (para macOS)
  if [[ "$OSTYPE" == "darwin"* ]]; then
    verificar_comando "brew" "Instala Homebrew con: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" || manejar_error "Homebrew es requerido para continuar."
  fi
  
  # Verificar Docker
  verificar_comando "docker" "Instala Docker Desktop desde https://www.docker.com/products/docker-desktop" || manejar_error "Docker es requerido para continuar."
  
  # Verificar kubectl
  if ! verificar_comando "kubectl" "Se instalará kubectl automáticamente."; then
    instalar_kubectl
  fi
  
  # Verificar minikube
  if ! verificar_comando "minikube" "Se instalará Minikube automáticamente."; then
    instalar_minikube
  fi
  
  mostrar_mensaje "exito" "Todos los requisitos están satisfechos."
}

# Función para instalar kubectl
instalar_kubectl() {
  mostrar_mensaje "info" "Instalando kubectl..."
  
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v brew &> /dev/null; then
      brew install kubectl || manejar_error "No se pudo instalar kubectl con Homebrew."
    else
      # Instalación manual para macOS
      curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/amd64/kubectl"
      chmod +x kubectl
      sudo mv kubectl /usr/local/bin/ || manejar_error "No se pudo mover kubectl a /usr/local/bin/. Ejecuta el script con sudo."
    fi
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Instalación para Linux
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/ || manejar_error "No se pudo mover kubectl a /usr/local/bin/. Ejecuta el script con sudo."
  else
    manejar_error "Sistema operativo no soportado para la instalación automática de kubectl."
  fi
  
  mostrar_mensaje "exito" "kubectl instalado correctamente."
}

# Función para instalar minikube
instalar_minikube() {
  mostrar_mensaje "info" "Instalando Minikube..."
  
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v brew &> /dev/null; then
      brew install minikube || manejar_error "No se pudo instalar Minikube con Homebrew."
    else
      # Instalación manual para macOS
      curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64
      chmod +x minikube-darwin-amd64
      sudo mv minikube-darwin-amd64 /usr/local/bin/minikube || manejar_error "No se pudo mover minikube a /usr/local/bin/. Ejecuta el script con sudo."
    fi
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Instalación para Linux
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    chmod +x minikube-linux-amd64
    sudo mv minikube-linux-amd64 /usr/local/bin/minikube || manejar_error "No se pudo mover minikube a /usr/local/bin/. Ejecuta el script con sudo."
  else
    manejar_error "Sistema operativo no soportado para la instalación automática de Minikube."
  fi
  
  mostrar_mensaje "exito" "Minikube instalado correctamente."
}

# Función para iniciar minikube
iniciar_minikube() {
  mostrar_mensaje "info" "Iniciando cluster de Minikube..."
  
  # Detener Minikube si ya está en ejecución
  if minikube status &> /dev/null; then
    mostrar_mensaje "alerta" "Minikube ya está en ejecución. Reiniciando..."
    minikube stop
  fi
  
  # Determinar el driver a utilizar
  local driver="docker"
  if [[ "$OSTYPE" == "darwin"* ]] && command -v hyperkit &> /dev/null; then
    driver="hyperkit"
  fi
  
  # Iniciar Minikube con recursos adecuados
  mostrar_mensaje "info" "Iniciando Minikube con driver: $driver"
  minikube start --driver=$driver \
    --cpus=2 \
    --memory=4096 \
    --disk-size=20g \
    --kubernetes-version=stable || manejar_error "No se pudo iniciar Minikube."
  
  # Habilitar addons necesarios
  mostrar_mensaje "info" "Habilitando complementos necesarios..."
  minikube addons enable ingress
  minikube addons enable metrics-server
  
  # Verificar que el cluster está en funcionamiento
  kubectl cluster-info || manejar_error "No se pudo verificar la información del cluster."
  
  mostrar_mensaje "exito" "Cluster de Minikube iniciado correctamente."
}

# Función para crear y aplicar manifiestos de pod security
configurar_pod_security() {
  mostrar_mensaje "info" "Configurando laboratorio de Pod Security Standards..."
  
  # Crear directorio temporal para manifiestos
  local tmp_dir=$(mktemp -d)
  
  # Crear manifiesto del namespace
  cat > "$tmp_dir/namespace.yaml" << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: pod-security-demo
  labels:
    # Pod Security Standards enforcement
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    
    # Pod Security Standards audit
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    
    # Pod Security Standards warn
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
EOF

  # Crear manifiesto de recursos
  cat > "$tmp_dir/resources.yaml" << EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-nginx-sa
  namespace: pod-security-demo

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-nginx
  namespace: pod-security-demo
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-nginx
  template:
    metadata:
      labels:
        app: secure-nginx
    spec:
      serviceAccountName: secure-nginx-sa
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginx:1.21-alpine
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
          readOnlyRootFilesystem: true
          runAsUser: 101   # nginx user in the nginx image
          runAsGroup: 101  # nginx group in the nginx image
        ports:
        - containerPort: 8080
          name: http
        resources:
          limits:
            cpu: 500m
            memory: 256Mi
          requests:
            cpu: 100m
            memory: 128Mi
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: var-run
          mountPath: /var/run
        - name: var-cache-nginx
          mountPath: /var/cache/nginx
        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: tmp-volume
        emptyDir:
          medium: Memory
      - name: var-run
        emptyDir: {}
      - name: var-cache-nginx
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: secure-nginx-svc
  namespace: pod-security-demo
spec:
  selector:
    app: secure-nginx
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-nginx-network-policy
  namespace: pod-security-demo
spec:
  podSelector:
    matchLabels:
      app: secure-nginx
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: TCP
      port: 53
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
EOF

  # Aplicar manifiestos
  mostrar_mensaje "info" "Aplicando manifiesto del namespace..."
  kubectl apply -f "$tmp_dir/namespace.yaml" || manejar_error "Error al aplicar el namespace."
  
  mostrar_mensaje "info" "Aplicando recursos de seguridad..."
  kubectl apply -f "$tmp_dir/resources.yaml" || manejar_error "Error al aplicar los recursos."
  
  # Limpiar archivos temporales
  rm -rf "$tmp_dir"
  
  mostrar_mensaje "exito" "Laboratorio de Pod Security Standards configurado correctamente."
}

# Función para verificar la implementación
verificar_implementacion() {
  mostrar_mensaje "info" "Verificando implementación del laboratorio..."
  
  # Esperar a que los pods estén listos
  kubectl wait --namespace=pod-security-demo --for=condition=ready pods --selector=app=secure-nginx --timeout=120s
  
  # Mostrar estado de los recursos
  mostrar_mensaje "info" "Namespaces:"
  kubectl get ns pod-security-demo -o yaml | grep pod-security
  
  mostrar_mensaje "info" "Pods en namespace pod-security-demo:"
  kubectl get pods -n pod-security-demo
  
  mostrar_mensaje "info" "Servicios en namespace pod-security-demo:"
  kubectl get svc -n pod-security-demo
  
  mostrar_mensaje "info" "Políticas de red:"
  kubectl get networkpolicies -n pod-security-demo
  
  mostrar_mensaje "exito" "Verificación completada."
}

# Función para mostrar información de acceso
mostrar_info_acceso() {
  mostrar_mensaje "info" "Información de acceso al laboratorio:"
  
  echo -e "${AZUL}===============================================${NC}"
  echo -e "${VERDE}Laboratorio de Kubernetes con Minikube${NC}"
  echo -e "${AZUL}===============================================${NC}"
  echo -e "${AMARILLO}Para acceder al servicio nginx seguro:${NC}"
  echo -e "  kubectl port-forward -n pod-security-demo svc/secure-nginx-svc 8080:80"
  echo -e "${AMARILLO}Luego visita:${NC} http://localhost:8080"
  echo -e ""
  echo -e "${AMARILLO}Para obtener información del cluster:${NC}"
  echo -e "  minikube dashboard"
  echo -e ""
  echo -e "${AMARILLO}Para eliminar el laboratorio:${NC}"
  echo -e "  kubectl delete ns pod-security-demo"
  echo -e "${AZUL}===============================================${NC}"
}

# Función principal
main() {
  # Comprobar que se está ejecutando como usuario normal (no root)
  if [ $(id -u) -eq 0 ]; then
    manejar_error "Este script no debe ejecutarse como root. Por favor, ejecuta como usuario normal."
  fi

  # Mostrar banner de inicio
  mostrar_mensaje "info" "Iniciando configuración del laboratorio de Kubernetes con Minikube"
  echo -e "${AZUL}=================================================================${NC}"
  echo -e "${AZUL}||                                                             ||${NC}"
  echo -e "${AZUL}||             LABORATORIO DE MINIKUBE PARA                    ||${NC}"
  echo -e "${AZUL}||          SEGURIDAD DE PODS EN KUBERNETES                    ||${NC}"
  echo -e "${AZUL}||                                                             ||${NC}"
  echo -e "${AZUL}=================================================================${NC}"
  echo ""

  # Ejecutar pasos en orden con manejo de errores
  trap 'manejar_error "Se produjo un error durante la ejecución del script."' ERR

  # Paso 1: Verificar requisitos del sistema
  verificar_requisitos

  # Paso 2: Iniciar Minikube
  iniciar_minikube

  # Paso 3: Configurar Pod Security Standards
  configurar_pod_security

  # Paso 4: Verificar la implementación
  verificar_implementacion

  # Paso 5: Mostrar información de acceso
  mostrar_info_acceso

  # Desactivar el trap de errores
  trap - ERR

  # Mensaje final
  mostrar_mensaje "exito" "¡Laboratorio configurado correctamente! Sigue las instrucciones anteriores para acceder."
  return 0
}

# Ejecutar la función principal
main "$@"
