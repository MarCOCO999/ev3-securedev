// Envía una notificación por correo sin que un error de SMTP haga fallar el pipeline
def notificar(String asunto, String cuerpo) {
    try {
        mail to: env.NOTIFY_EMAIL, subject: asunto, body: cuerpo
    } catch (err) {
        echo "ADVERTENCIA: no se pudo enviar el correo de notificación (${err.getMessage()})"
    }
}

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        disableConcurrentBuilds()
        timestamps()
    }

    parameters {
        booleanParam(name: 'RUN_DEPENDENCY_CHECK', defaultValue: true,
                     description: 'Ejecutar OWASP Dependency-Check (la primera vez descarga la base NVD y demora)')
        booleanParam(name: 'RUN_ZAP', defaultValue: true,
                     description: 'Ejecutar el escaneo dinámico con OWASP ZAP')
    }

    environment {
        APP_IMAGE    = 'ev3-app'
        APP_NAME     = 'ev3-app'
        NETWORK      = 'devsecops'
        APP_URL      = 'http://ev3-app:5000'
        NOTIFY_EMAIL = 'marco.contreras002@gmail.com'
    }

    stages {

        stage('Build') {
            steps {
                echo 'Construyendo la imagen Docker de la aplicación...'
                sh '''
                    {
                      echo "Build:   ${BUILD_NUMBER}"
                      echo "Fecha:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
                      echo "Commit:  $(git rev-parse HEAD)"
                      echo "Autor:   $(git log -1 --pretty=format:'%an <%ae>')"
                      echo "Mensaje: $(git log -1 --pretty=format:'%s')"
                    } > build-info.txt
                    cat build-info.txt

                    docker build -t ${APP_IMAGE}:${BUILD_NUMBER} -t ${APP_IMAGE}:latest .

                    python3 -m venv .sec
                    .sec/bin/pip install -q --upgrade pip
                    .sec/bin/pip install -q bandit pip-audit
                '''
            }
        }

        stage('Test') {
            steps {
                echo 'Ejecutando pruebas funcionales y de seguridad dentro del contenedor...'
                script {
                    def rc = sh(returnStatus: true, script: '''
                        docker rm -f ev3-test 2>/dev/null || true
                        docker run --name ev3-test ${APP_IMAGE}:${BUILD_NUMBER} \
                          sh -c "pip install -q pytest && python -m pytest tests -v --junitxml=/tmp/test-results.xml"
                    ''')
                    sh 'docker cp ev3-test:/tmp/test-results.xml test-results.xml || true; docker rm -f ev3-test || true'
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                    if (rc != 0) {
                        unstable('Hay pruebas fallidas (ver pruebas de seguridad en Test Result)')
                    }
                }
            }
        }

        stage('Analyze (SAST)') {
            steps {
                echo 'Análisis estático con Bandit y SonarQube...'
                sh '''
                    .sec/bin/bandit -r . -x ./tests,./.sec,./infra,./scripts -f json -o bandit-report.json || true
                    .sec/bin/bandit -r . -x ./tests,./.sec,./infra,./scripts -f html -o bandit-report.html || true
                    .sec/bin/bandit -r . -x ./tests,./.sec,./infra,./scripts -f txt || true
                '''
                script {
                    def scannerHome = tool 'sonar-scanner'
                    withSonarQubeEnv('sonarqube') {
                        sh "${scannerHome}/bin/sonar-scanner -Dsonar.projectVersion=${BUILD_NUMBER}"
                    }
                }
            }
        }

        stage('Security Test - Dependencias') {
            steps {
                echo 'Revisando dependencias con pip-audit y OWASP Dependency-Check...'
                sh '''
                    .sec/bin/pip-audit -r requirements.txt --no-deps --disable-pip -f json -o pip-audit.json || true
                    .sec/bin/pip-audit -r requirements.txt --no-deps --disable-pip -f markdown -o pip-audit.md || true
                    .sec/bin/pip-audit -r requirements.txt --no-deps --disable-pip --desc || true
                '''
                script {
                    if (params.RUN_DEPENDENCY_CHECK) {
                        withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_KEY')]) {
                            dependencyCheck odcInstallation: 'dependency-check',
                                additionalArguments: "--scan requirements.txt --out . --format HTML --format JSON --format XML " +
                                                     "--enableExperimental --disableOssIndex --disableAssembly --nvdApiKey ${env.NVD_KEY}"
                        }
                        dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                    } else {
                        echo 'Dependency-Check omitido por parámetro.'
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                echo 'Desplegando la aplicación en el entorno de prueba...'
                sh '''
                    docker rm -f ${APP_NAME} 2>/dev/null || true
                    docker run -d --name ${APP_NAME} --network ${NETWORK} -p 5000:5000 \
                      --restart unless-stopped ${APP_IMAGE}:${BUILD_NUMBER}

                    for i in $(seq 1 20); do
                      if curl -fs "${APP_URL}/hello?name=Jenkins"; then echo; echo "Aplicación disponible"; exit 0; fi
                      sleep 2
                    done
                    echo "La aplicación no respondió"; docker logs ${APP_NAME}; exit 1
                '''
            }
        }

        stage('Security Test - OWASP ZAP (DAST)') {
            when { expression { params.RUN_ZAP } }
            steps {
                echo 'Escaneo dinámico con OWASP ZAP sobre la aplicación desplegada...'
                script {
                    sh '''
                        docker rm -f zap-scan 2>/dev/null || true
                        docker volume create zap-wrk > /dev/null
                        # Permite que el usuario "zap" del contenedor escriba los reportes en el volumen
                        docker run --rm -u root -v zap-wrk:/zap/wrk ghcr.io/zaproxy/zaproxy:stable \
                          sh -c "rm -f /zap/wrk/zap-report.* && chmod 777 /zap/wrk"
                    '''
                    // Código 3 = ZAP no pudo iniciar (p. ej. falla de red al actualizar complementos): se reintenta
                    def rc = 3
                    for (int intento = 1; intento <= 3 && rc == 3; intento++) {
                        echo "Ejecutando OWASP ZAP (intento ${intento} de 3)..."
                        rc = sh(returnStatus: true, script: '''
                            docker rm -f zap-scan 2>/dev/null || true
                            docker run --name zap-scan --network ${NETWORK} -v zap-wrk:/zap/wrk:rw \
                              ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
                              -t "${APP_URL}/hello?name=test" -m 2 -T 5 -I \
                              -r zap-report.html -J zap-report.json -w zap-report.md
                        ''')
                    }
                    sh '''
                        docker cp zap-scan:/zap/wrk/zap-report.html . || true
                        docker cp zap-scan:/zap/wrk/zap-report.json . || true
                        docker cp zap-scan:/zap/wrk/zap-report.md   . || true
                        docker rm -f zap-scan || true
                    '''
                    echo "Código de salida de ZAP: ${rc}"
                }
            }
        }

        stage('Security Report') {
            steps {
                echo 'Generando el resumen consolidado de seguridad (trazabilidad)...'
                script {
                    def rc = sh(returnStatus: true, script: 'python3 scripts/security_summary.py')
                    if (rc == 2) {
                        unstable('Se detectaron hallazgos de severidad ALTA/CRÍTICA. Ver security-summary.md')
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts allowEmptyArchive: true, fingerprint: true, artifacts:
                'build-info.txt, security-summary.md, test-results.xml, bandit-report.*, pip-audit.*, dependency-check-report.*, zap-report.*'
            publishHTML(target: [reportDir: '.', reportFiles: 'zap-report.html', reportName: 'OWASP ZAP',
                                 allowMissing: true, keepAll: true, alwaysLinkToLastBuild: true])
            publishHTML(target: [reportDir: '.', reportFiles: 'bandit-report.html', reportName: 'Bandit',
                                 allowMissing: true, keepAll: true, alwaysLinkToLastBuild: true])
            publishHTML(target: [reportDir: '.', reportFiles: 'dependency-check-report.html', reportName: 'Dependency-Check',
                                 allowMissing: true, keepAll: true, alwaysLinkToLastBuild: true])
        }
        success {
            echo 'Pipeline completado sin hallazgos críticos.'
        }
        unstable {
            notificar("[Jenkins] HALLAZGOS DE SEGURIDAD en ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                      "El pipeline terminó con hallazgos de seguridad o pruebas fallidas.\n\n" +
                      "Build: ${env.BUILD_URL}\nResumen: ${env.BUILD_URL}artifact/security-summary.md")
        }
        failure {
            notificar("[Jenkins] FALLO en ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                      "El pipeline falló. Revisar: ${env.BUILD_URL}console")
        }
        fixed {
            notificar("[Jenkins] CORREGIDO ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                      "El pipeline volvió a pasar sin hallazgos críticos: ${env.BUILD_URL}")
        }
    }
}