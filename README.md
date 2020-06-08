# klusterstatus
What klusterstatus is for : 

  - Sends all used images in your cluster to Anchore for vulnerability scan. 
  - Checks the actuality of the Pod images in a kubernetes cluster. 

## requirements
 - Python 3
 - Local running kubectl with access to your kubernetes cluster
 - Running Anchore (See docker-compose-anchore.yaml)

 ## limits
 - does not check the age of gcr.io images (Help wanted, since i was not able to find any information about gcr.io API )

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


## run
```
cp .env.example .env
vim .env
docker-compose up -d 
``` 
or 
```
docker-compose up -d -e PATH_LOCAL_KUBECONFIG=~/.kube/config
```

## Usage
usage: klusterstatus.py [-h] [-v] [-n NAMESPACES] [-N NAMESPACESBLACKLIST]
                        [-c CAPABILITIES] [-o {cli,json}]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -n NAMESPACES, --namespaces NAMESPACES
                        Coma separated whitelist of Namespaces to check
  -N NAMESPACESBLACKLIST, --namespacesblacklist NAMESPACESBLACKLIST
                        Coma separated blacklist of Namespaces to skip
  -c CAPABILITIES, --capabilities CAPABILITIES
                        Coma separated whitelist of capabilities to check
  -o {cli,json}, --output {cli,json}
                        report format

To check private Dockerub repositorys set export your credentials environment variables.
```
export DOCKER_USER=myfancyuser
export DOCKER_PASS=123456
```

## Result
```
./klusterstatus.py -n myApp -c NET_BIND_SERVICE 

Pod: myApp-zookeeper-1
Container: zookeeper
  Do not allow privilege escalation   : OK
  capabilities drop ALL               : OK
  capabilitiy "NET_BIND_SERVICE" whitelisted to add : OK
  Image: gcr.io/google_samples/k8szk:v3
  Vulnerabilies:                               
    High                              : 13/13
    Critical                          : 0/0
    Medium                            : 267/233
    Low                               : 193/107
    Negligible                        : 100/4
    Unknown                           : 0/0

Pod: myApp-mongodb-replicaset-1
  Do not allow privilege escalation   : OK
  capabilities drop ALL               : OK
  capabilitiy "NET_BIND_SERVICE" whitelisted to add : OK
  Vulnerabilies in mongo:3.6                               
    High                              : 0/0
    Critical                          : 0/0
    Medium                            : 32/2
    Low                               : 70/6
    Negligible                        : 76/0
    Unknown                           : 0/0
```


## Start Anchore locally
```
curl https://docs.anchore.com/current/docs/engine/quickstart/docker-compose.yaml > docker-compose-anchore.yaml
docker-compose -f docker-compose-anchore.yaml up -d 
```

## Todo
 - save reports in a database
 - build a GUI to see the reports
 - Helm charts for a clouddeployments