FROM python:3.10-alpine

ARG KUBECTL_VERSION="v1.17.0"
ENV KUBECONFIG="/kube.config"

#install kubectl
RUN apk --no-cache add curl 
RUN apk --no-cache add rpm

#RUN apt-get update && apt-get install -y apt-transport-https curl gnupg2 rpm; \
RUN echo https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl; \
curl -LO https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl ; \
chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl

#install gcloud
#RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && apt-get update -y && apt-get install google-cloud-sdk -y

#install kubeaudit https://github.com/Shopify/kubeaudit/tags
COPY --from=shopify/kubeaudit:v0.16 /kubeaudit /usr/local/bin/kubeaudit

#install trivy https://github.com/aquasecurity/trivy/tags
COPY --from=aquasec/trivy:0.21.0 /usr/local/bin/trivy /usr/local/bin/trivy

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

RUN apk del curl

COPY app/ app/