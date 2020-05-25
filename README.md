# klusterstatus
Checks the actuality of the Pod images in a kubernetes cluster

## requirements
 - Python 3
 - Local running kubectl with access to your kubernetes cluster

## Usage
usage: klusterstatus.py [-h] [-v] [-n NAMESPACES]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -n NAMESPACES, --namespaces NAMESPACES
                        Path to configfile