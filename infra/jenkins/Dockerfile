# Parte de la imagen usada en la actividad anterior (Jenkins + Python + Doxygen)
# y agrega el cliente de Docker para que el pipeline pueda construir y ejecutar contenedores.
FROM jenkins-doxygen

USER root
ARG DOCKER_VERSION=27.3.1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
       | tar -xz --strip-components=1 -C /usr/local/bin docker/docker
USER jenkins
