pipeline {
    agent none

    triggers {
        githubPush()
    }

    environment {
        IMAGE_NAME = "raichu08/todo-auth"
        IMAGE_TAG = "v${BUILD_NUMBER}"
    }

    stages {

        stage('Checkout Code') {
            agent { label 'dev' }
            steps {
                echo "Fetching latest code from GitHub..."
                checkout scm
            }
        }
    

        stage('Build Docker Image') {
           agent { label 'dev' }
            steps {
                script {
                    echo "Building Docker image..."
                    sh """
                        sudo docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
                    """
                }
            }
        }
        
        stage('Push to Dockerhub and Logout') {
            agent { label 'dev' }
            when {
                expression { currentBuild.currentResult == "SUCCESS" }
            }
            steps {
                script {
                    withCredentials([usernamePassword(
                        credentialsId: 'Dhub', 
                        usernameVariable: 'DOCKER_USER', 
                        passwordVariable: 'DOCKER_PASS'
                    )]) {
                         sh """
                            set -e
                            echo "Logging into Docker..."
                            echo "$DOCKER_PASS" | sudo docker login -u "$DOCKER_USER" --password-stdin
                            sudo docker push ${IMAGE_NAME}:${IMAGE_TAG}
                            sudo docker logout
                         """
                    }
                }
            }
        }
    }

    post {
        success {
            echo "Docker Build, Test and Push completed successfully! Now cleaning up"
            node('dev') {
                script {
                    sh """ 
                    sudo docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true
                    """
                }
            }
        }
        failure {
            echo "Docker Build, Test and Push failed! Now cleaning up"
            node('dev') {
                script {
                    sh """ 
                    sudo docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true
                    """
                }
            }
        }
    }
}
        
