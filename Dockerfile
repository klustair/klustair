#FROM debian:stable-slim
FROM python:3.8-slim-buster

ARG KUBECTL_VERSION="v1.17.0"
ENV DOCKER_USER=""
ENV DOCKER_PASS=""
ENV ANCHORE_CLI_USER="admin"
ENV ANCHORE_CLI_PASS="foobar"
ENV ANCHORE_CLI_URL="http://172.17.0.1:8228"
ENV KUBECONFIG="/kube.config"

#install kubectl
RUN apt-get update && apt-get install -y apt-transport-https curl; \
echo https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl; \
curl -LO https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl ; \
chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY klusterstatus.py klusterstatus.py