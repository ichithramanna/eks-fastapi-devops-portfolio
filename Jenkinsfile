pipeline {
    agent { label 'linux' }

    parameters {
        booleanParam(name: 'Sonarscan', defaultValue: true, description: 'Run SonarQube analysis')
    }

    environment {
        SONARQUBE_ENV  = 'Sonarscanner'
        SCANNER_HOME   = tool 'sonar-scanner'
        projectKey     = 'eks-fastapi-devops-portfolio'
        JFROG_REGISTRY = 'trialnnbkyv.jfrog.io'
        DOCKER_REPO    = 'trialnnbkyv.jfrog.io/eks-fastapi-devops-p-docker-local/eks-fastapi-backend'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scmGit(
                    branches: [[name: '*/main']],
                    extensions: [],
                    userRemoteConfigs: [[url: 'https://github.com/ichithramanna/eks-fastapi-devops-portfolio.git']]
                )
            }
        }

        stage('Install & Test') {
            steps {
                dir('backend') {
                    sh '''
                      python3 -m venv venv
                      . venv/bin/activate
                      pip install -r requirements.txt pytest pytest-cov httpx
                      pytest tests/ --cov=app --cov-report=xml:coverage.xml -v
                    '''
                }
            }
        }

        stage('SonarQube Analysis') {
            when { expression { params.Sonarscan } }
            steps {
                dir('backend') {
                    withSonarQubeEnv("${SONARQUBE_ENV}") {
                        sh "${SCANNER_HOME}/bin/sonar-scanner -Dsonar.projectKey=${projectKey}"
                    }
                }
            }
        }

        stage('Quality Gate') {
            when { expression { params.Sonarscan } }
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }

        stage('Docker Build') {
            steps {
                dir('backend') {
                    sh "docker build -t ${DOCKER_REPO}:${env.BUILD_NUMBER} ."
                }
            }
        }

        stage('Publish to JFrog') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'Jfrog-creds',
                    usernameVariable: 'username',
                    passwordVariable: 'password'
                )]) {
                    sh """
                      echo "${password}" | docker login ${JFROG_REGISTRY} -u "${username}" --password-stdin
                      docker push ${DOCKER_REPO}:${env.BUILD_NUMBER}
                      docker tag  ${DOCKER_REPO}:${env.BUILD_NUMBER} ${DOCKER_REPO}:latest
                      docker push ${DOCKER_REPO}:latest
                    """
                }
            }
            post {
                always {
                    cleanWs()
                }
            }
        }
    }

    post {
        success {
            echo "✅ Pipeline succeeded! Image pushed: ${DOCKER_REPO}:${env.BUILD_NUMBER}"
        }
        failure {
            echo '❌ Pipeline failed. Check the logs above.'
        }
    }
}
