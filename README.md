<p align="center"><img src="https://raw.githubusercontent.com/klustair/klustair-frontend/master/docs/img/klustair.png" width="200"></p>

# <a href='https://github.com/klustair/klustair'>KlustAIR Scanner</a>
The Klustair scanner scanns your Kubernetes namespaces for the used images and submits them to Anchore. This is the scanner part. 

<p>
<span style="color:red">
<b>INFORMATION</b>
This runner is deprecated in favor of the new klustair-cli. For Klustair newer than v0.6.0 please use the <a href="https://github.com/klustair/klustair-cli">klustair-cli</a> written in GO. 
</span>
</p>
<br>

### Related Klustair projects: 
- <a href="https://github.com/klustair/klustair-frontend">Klustair Frontend</a> to view the scanner results
- <a href="https://github.com/klustair/klustair-helm">Klustair Helm charts</a> to spin up Anchore and Klustair

### Related opensource projects
- <a href="https://github.com/aquasecurity/trivy">trivy</a> A Simple and Comprehensive Vulnerability Scanner for Containers and other Artifacts
- (DEPRECATED) <a href="https://github.com/anchore/anchore-engine">anchore-engine</a> A service that analyzes docker images and applies user-defined acceptance policies to allow automated container image validation and certification
- <a href="https://github.com/Shopify/kubeaudit">kubeaudit</a> kubeaudit helps you audit your Kubernetes clusters against common security controls

## Requirements
 - Python 3
 - Running Anchore (See docker-compose-anchore.yaml)

## Usage
```
usage: runner.py [-h] [-v] [-n NAMESPACES] [-N NAMESPACESBLACKLIST]
                 [-k KUBEAUDIT] [-l LABEL] [-a] [-t] [-c TRIVYCREDENTIALS]

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
  -l LABEL, --label LABEL
                        A optional title for your run
  -a, --anchore         Run Anchore vulnerability checks
  -t, --trivy           Run Trivy vulnerability checks
  -c TRIVYCREDENTIALSPATH, --trivycredentialspath TRIVYCREDENTIALSPATH
                        Path to repo credentials for trivy
  -ld LIMITDATE, --limitDate LIMITDATE
                        Remove reports older than X days
  -ln LIMITNR, --limitNr LIMITNR
                        Keep only X reports
  -C CONFIGKEY, --limitNr CONFIGKEY
                        Load remote configuration from frontend
  -H APIHOST, --limitNr APIHOST
                        Remote API-host address [example: https://localhost:8443]
```

## ENV vars
```
export KLUSTAIR_NAMESPACES=
export KLUSTAIR_NAMESPACEBLACKLIST=
export KLUSTAIR_KUBEAUDIT=
export KLUSTAIR_TRIVYCREDENTIALSPATH=
```

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
source env/bin/activate
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