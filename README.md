# klusterstatus
Checks the actuality of the Pod images in a kubernetes cluster

## requirements
 - Python 3
 - Local running kubectl with access to your kubernetes cluster

 ## limits
 - Does not check the age of Image or pod
 - does not check gcr.io images (Help wanted, since i was not able to find any information about gcr.io API )

## Usage
usage: klusterstatus.py [-h] [-v] [-n NAMESPACES]

optional arguments:\
  -h, --help            show this help message and exit\
  -v, --verbose         increase output verbosity\
  -n NAMESPACES, --namespaces NAMESPACES
                        Coma separated whitelist of Namespaces to check

To check private Dockerub repositorys set export your credentials environment variables.

```
export DOCKER_USER=myfancyuser
export DOCKER_PASS=123456
```

## Result
```
./klusterstatus.py
Namespace: cattle-system ------------------------------

Pod name: cattle-cluster-agent-85c4f7d47d-jhxnp
Container image: rancher/rancher-agent:v2.3.6
Container started at: 2020-05-18T11:55:45Z
Image last_updated  : 2020-03-31T01:07:27.147795Z
======> OK

Pod name: cattle-node-agent-4sj6f
Container image: rancher/rancher-agent:v2.3.6
Container started at: 2020-05-18T11:56:22Z
Image last_updated  : 2020-03-31T01:07:27.147795Z
======> OK

....
```