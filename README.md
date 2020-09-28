<p align="center"><img src="https://raw.githubusercontent.com/mms-gianni/klustair-frontend/master/docs/img/klustair.png" width="200"></p>

# <a href='https://github.com/mms-gianni/klustair'>KlustAIR Scanner</a>
The Klustair scanner scanns your Kubernetes namespaces for the used images and submits them to Anchore. This is the scanner part. 

### Related Klustair projects: 
- <a href="https://github.com/mms-gianni/klustair-frontend">Klustair Frontend</a> to view the scanner results
- <a href="https://github.com/mms-gianni/klustair-helm">Klustair Helm charts</a> to spin up Anchore and Klustair

### Related opensource projects
- <a href="https://github.com/anchore/anchore-engine">anchore-engine</a> A service that analyzes docker images and applies user-defined acceptance policies to allow automated container image validation and certification
- <a href="https://github.com/Shopify/kubeaudit">kubeaudit</a> kubeaudit helps you audit your Kubernetes clusters against common security controls

## Requirements
 - Python 3
 - Running Anchore (See docker-compose-anchore.yaml)

## Usage
```
scanner.py [-h] [-v] [-n NAMESPACES] [-N NAMESPACESBLACKLIST]
                        [-c CAPABILITIES] [-o {cli,json}]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -n NAMESPACES, --namespaces NAMESPACES
                        Coma separated whitelist of Namespaces to check
  -N NAMESPACESBLACKLIST, --namespacesblacklist NAMESPACESBLACKLIST
                        Coma separated blacklist of Namespaces to skip
  -k KUBEAUDIT, --kubeaudit KUBEAUDIT
                        Coma separated list of audits to run. default: 'all',
                        disable: 'none'
````

## Run in Docker
```
cp .env.example .env
vim .env
docker-compose up -d 
``` 
or 
```
docker-compose up -d -e PATH_LOCAL_KUBECONFIG=~/.kube/config
```

## Start Anchore locally
```
curl https://docs.anchore.com/current/docs/engine/quickstart/docker-compose.yaml > docker-compose-anchore.yaml
docker-compose -f docker-compose-anchore.yaml up -d 
```

## develop
```
python3 -m venv env
source develop/bin/activate
pip install -r requirements.txt

deactivate
```

## build
```
cp .env.example .env
vim .env
docker compose build
```
or
```
docker compose build
```