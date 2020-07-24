#!/usr/bin/env python3

import subprocess, json, sys
import requests
import re
import logging as log
import argparse
import os
from datetime import datetime
import pprint
import pymongo

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

DOCKER_TOKEN=''

result = {
    'pods': [],
}

def printStatus(item, status):
    if status == 'OK':
        print(OKGREEN+'OK   : '+ENDC+item)
    elif status == 'FAIL':
        print(FAIL+'FAIL : '+ENDC+item)

def check_securityContext(containers,capabilitiesWhitelist):
    for container in containers:
        container['checkresults'] = []

        if 'securityContext' not in container: 
            continue

        if 'allowPrivilegeEscalation' in container['securityContext']: 
            checkresult = {
                'name': 'allowPrivilegeEscalation',
                'description': 'Do not allow privilege escalation'
            }
            if container['securityContext']['allowPrivilegeEscalation'] == False:
                checkresult['result']=1
                log.debug('allowPrivilegeEscalation=False : OK')
            else:
                checkresult['result']=0
                log.debug('allowPrivilegeEscalation=False : FAIL')
            container['checkresults'].append(checkresult)

        if 'capabilities' in container['securityContext']:
            checkresult = {
                'name': 'allowPrivilegeEscalation',
                'description': 'capabilities drop ALL',
                'result': 1
            }
            if 'ALL' in container['securityContext']['capabilities']['drop']:
                checkresult['result']=1
                log.debug('capabilities drop ALL : OK')
            else:
                checkresult['result']=0
                log.debug('capabilities drop ALL : FAIL')
            container['checkresults'].append(checkresult)
            
            log.debug('capabilities: ')
            if 'add' in container['securityContext']['capabilities']:
                for capability in container['securityContext']['capabilities']['add']:
                    log.debug(' - '+capability)
                    if capability not in capabilitiesWhitelist:
                        container['checkresults'].append({
                            'name': 'capabilityWhitelist',
                            'description': 'capabilitiy "'+capability+'" not whitelisted to add',
                            'result': 0
                        })
                    else:
                        container['checkresults'].append({
                            'name': 'capabilityWhitelist',
                            'description': 'capabilitiy "'+capability+'" whitelisted to add',
                            'result': 1
                        })

            else:
                container['checkresults'].append({
                    'name': 'noExplicitCapabilitie',
                    'description': 'no explicit add of capabilities',
                    'result': 0
                })


def checkImage_quayio(image, imageID):
    [(repository,digest)]  = re.findall(r'docker-pullable://quay\.io/([\w\/-]+)@(sha256:\w+)', imageID)
    [(tag)] = re.findall(r'[\w\/-]+:([\w\.-]+)', image)

    repositoryUrl = "https://quay.io/api/v1/repository/{}/tag/".format(repository)
    log.debug("repositoryUrl: {}".format(repositoryUrl))
    try:
        r = requests.get(repositoryUrl)
        tagslist = json.loads(r.content)
    except:
        log.error("ERROR: cant load tagslist")
        return
    for tagMeta in tagslist['tags']:
        if tagMeta['name'] == tag:
            manifest_digest = tagMeta['manifest_digest']
            last_modified = tagMeta['last_modified']
    log.debug("Image last_modified: {}".format(last_modified))

    manifestUrl = "https://quay.io/api/v1/repository/{}/manifest/{}".format(repository, manifest_digest)
    log.debug("manifestUrl: {}".format(manifestUrl))
    try:
        r = requests.get(manifestUrl)
        remoteimage = json.loads(r.content)
    except:
        log.error("ERROR: cant load JSON")
        return
    
    manifests=json.loads(remoteimage['manifest_data'])
    log.debug(remoteimage['manifest_data'])

    if 'manifests' in manifests:
        for image in manifests['manifests']:
            if image['platform']['architecture'] == 'amd64':
                if digest ==  image['digest']:
                    log.debug(OKGREEN+'======> OK '+ENDC)
                else:
                    log.debug(FAIL+'======> UPDATE '+ENDC)
                    log.debug('remote: '+image['digest'])
                    log.debug('local : '+digest)

def checkImage_dockerhub(container):

    checkresult = {
        'name': 'imageFreshnes',
        'description': 'latest version of this image',
        'result': 1
    }

    if not  container['ready']:
        print("WARNING: Container not in ready state. Aborting image checks on running container")
        container['checkresults'].append({
            'name': 'containerNotRunning',
            'description': 'Container not in ready state. Aborting image checks on running container',
            'result': 2
        })
        return
    [(repository,digest)]  = re.findall(r'docker-pullable://([\w\/-]+)@(sha256:\w+)', container['imageID'])

    [(repository,tag)] = re.findall(r'([\w\/-]+):([\w\.-]+)', container['image'])

    if not re.search('/', repository):
        repository = 'library/'+repository

    url = "https://hub.docker.com/v2/repositories/{}/tags/{}".format(repository, tag)
    log.debug("url: {}".format(url))

    try:
        r = requests.get(url, headers = {'Authorization': 'JWT '+DOCKER_TOKEN})
        remoteimage = json.loads(r.content)
    except:
        log.error("ERROR: cant load JSON")
        return

    if 'last_updated' in remoteimage and 'running' in container['state']:
        log.debug("Image last_updated  : {}".format(remoteimage['last_updated']))
        image_last_updated = datetime.strptime(remoteimage['last_updated'], "%Y-%m-%dT%H:%M:%S.%fZ")
        container_startedAt = datetime.strptime(container['state']['running']['startedAt'], "%Y-%m-%dT%H:%M:%SZ")
        is_latestimage = image_last_updated < container_startedAt

    if 'images' in remoteimage:
        for image in remoteimage['images']:
            if image['architecture'] == 'amd64' and image['os'] == 'linux':
                if digest == image['digest'] or is_latestimage:
                    log.debug(OKGREEN+'======> OK '+ENDC)
                    checkresult['result'] = 1
                else:
                    checkresult['result'] = 0
                    log.debug(FAIL+'======> UPDATE '+ENDC)
                    log.debug('remote: '+image['digest'])
                    log.debug('local : '+digest)

    container['checkresults'].append(checkresult)

def login_dockerub():
    global DOCKER_TOKEN
    dockerUser = os.getenv('DOCKER_USER', False)
    dockerPass = os.getenv('DOCKER_PASS', False)

    log.debug('Docker User: {}'.format(os.getenv('DOCKER_USER', "not set")))
    log.debug('Docker Pass: {}'.format(os.getenv('DOCKER_PASS', "not set")))

    if dockerUser and dockerPass:
        data = {"username": dockerUser, "password": dockerPass}
        url = "https://hub.docker.com/v2/users/login/"

        try:
            r = requests.post(url, data = data)
            DOCKER_TOKEN = json.loads(r.content)['token']
        except:
            log.error("cant login to docker hub")
            return
        log.debug(DOCKER_TOKEN)

def normalize_containerstatus(containers, containerStatuses):
    containers_r = []
    for container in containers: 
        for containerStatus in containerStatuses:
            if containerStatus['image'] == container['image']:
                container.update(containerStatus)
        containers_r.append(container)
        
    return containers_r

def checkImage(containers): 
    for container in containers:

        print("checking Container image: {}".format(container['image']))
        log.debug("Container name: {}".format(container['name']))

        if 'state' in container and 'running' in container['state']:
            log.debug("Container started at: {}".format(container['state']['running']['startedAt']))
        
        if 'imageID' not in container:
            continue

        log.debug("Container imageID: {}".format(container['imageID']))
        if re.search(r'gcr.io',container['image']):
            log.debug("repository: gcr.io")
            container['repository'] = ' gcr.io'
        elif re.search(r'quay.io',container['image']):
            log.debug("repository: quay.io")
            container['repository'] = 'quay.io'
            checkImage_quayio(container['image'], container['imageID'])
        else:
            container['repository'] = 'dockerhub'
            checkImage_dockerhub(container)


def run():
    global result

    login_dockerub()

    checktime = datetime.now()
    namespaces = json.loads(subprocess.run(["kubectl", "get", "namespaces", "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))

    for namespace in namespaces['items']:
        nsName=namespace['metadata']['name']
        nsUid=namespace['metadata']['uid']
        nsCreationTimestamp=namespace['metadata']['creationTimestamp']

        if namespacesWhitelist and nsName not in namespacesWhitelist: 
            continue
        if namespacesBlacklist and nsName in namespacesBlacklist: 
            continue

        print("checking Namespace: {} ------------------------------".format(nsName))
        log.debug("Namespace UID: {}".format(nsUid))
        log.debug("Namespace creation: {}".format(nsCreationTimestamp))
        
        pods = json.loads(subprocess.run(["kubectl", "get", "pods", "-n", nsName, "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        for pod in pods['items']:
            print("checking Pod name: {}".format(pod['metadata']['name']))
            log.debug("Pod creationTimestamp: {}".format(pod['metadata']['creationTimestamp']))
            
            if 'containerStatuses' in pod['status']:
                containers_r = normalize_containerstatus(pod['spec']['containers'] , pod['status']['containerStatuses'])

                check_securityContext(containers_r, capabilitiesWhitelist)
                checkImage(containers_r)
            get_anchoreVulnerabilities(containers_r)

            # most items have invalid keys
            if 'annotations' in pod['metadata']:
                del pod['metadata']['annotations']
            if 'labels' in pod['metadata']:
                del pod['metadata']['labels']

            pod_r = {
                'metadata': pod['metadata'],
                'checktime' : checktime,
                'containers': containers_r
            }
            result['pods'].append(pod_r)
            print("")

def get_anchoreVulnerabilities(containers):
    for container in containers:
        #pprint.pprint(container)
        #anchore-cli --json --u admin --p foobar image vuln gcr.io/google_samples/k8szk:v3 all
        vulnerabilities = subprocess.run(["anchore-cli", "--json", "image", "vuln", container['image'], "all"], stdout=subprocess.PIPE).stdout.decode('utf-8')
        vuln_json = json.loads(vulnerabilities)


        vulnsum = {
            'Critical': {
                'total': 0,
                'fixed': 0
            },
            'High': {
                'total': 0,
                'fixed': 0
            },
            'Medium': {
                'total': 0,
                'fixed': 0
            },
            'Low': {
                'total': 0,
                'fixed': 0
            },
            'Negligible': {
                'total': 0,
                'fixed': 0
            },
            'Unknown': {
                'total': 0,
                'fixed': 0
            }
        }
        #pprint.pprint(vuln_json)
        if 'message' in vuln_json and vuln_json['message'] == 'cannot use input image string (no discovered imageDigest)':
            print('{}Image {} is not in anchore yet{}'.format("\033[91m", container['image'], "\033[0m"))
            subprocess.run(["anchore-cli", "--json", "image", "add", container['image']], stdout=subprocess.PIPE).stdout.decode('utf-8')
            continue
        elif 'message' in vuln_json:
            print('{}Image {} is not in anchore yet: {} {}'.format("\033[91m", container['image'], vuln_json['message'], "\033[0m"))
            continue
        else:
            for vuln in vuln_json['vulnerabilities']:
                vulnsum[vuln['severity']]['total'] += 1
                if vuln['fix'] != 'None':
                    vulnsum[vuln['severity']]['fixed'] += 1

        container['vulnsum'] = vulnsum
        
        container['vulnerabilies'] = vuln_json


def display_cliresult():
    global result
    #HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    #WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    #BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    status = [
        FAIL+'FAIL'+ENDC,
        OKGREEN+'OK'+ENDC,
        OKBLUE+'UNKNOWN'+ENDC
    ]

    #pprint.pprint(result)
    for pod in result['pods']:
        print("")
        print('Pod: {}'.format(pod['metadata']['name']))
        for container in pod['containers']:
            for checkresult in container['checkresults']:
                print('  {} : {}'.format(checkresult['description'].ljust(35), status[checkresult['result']]))

            print('  {}Vulnerabilies in {}                               {}'.format(UNDERLINE, container['image'], ENDC))
            for severity, numbers in container['vulnsum'].items():
                print('    {} : {}/{}'.format(severity.ljust(33), numbers['total'], numbers['fixed']))

def safe_result():
    mongodbConnection = os.getenv('MONGODB_CONNECTION', False)
    #mongodbConnection = 'mongodb://klustair-mongo-db:27017/klustair'
    #mongodbConnection = 'mongodb://localhost:27017/klustair'

    if not mongodbConnection:
        return
    
    mdbClient = pymongo.MongoClient(mongodbConnection)
    db = mdbClient["klustair"]
    podsDB = db["pods"]
    
    podsDB.insert_many(result['pods'])

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', required=False, help="increase output verbosity")
    parser.add_argument("-n", "--namespaces", required=False, help="Coma separated whitelist of Namespaces to check")
    parser.add_argument("-N", "--namespacesblacklist", required=False, help="Coma separated blacklist of Namespaces to skip")
    parser.add_argument("-c", "--capabilities", required=False, help="Coma separated whitelist of capabilities to check")
    parser.add_argument("-o", "--output", default='cli', choices=['cli', 'json'], help="report format")

    args = parser.parse_args()
    if args.verbose:
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.DEBUG)

    namespacesWhitelist = []
    if args.namespaces:
        namespacesWhitelist = args.namespaces.split(',')

    namespacesBlacklist = []
    if args.namespacesblacklist:
        namespacesBlacklist = args.namespacesblacklist.split(',')

    capabilitiesWhitelist = []
    if args.capabilities:
        capabilitiesWhitelist = args.capabilities.split(',')

    run()
    safe_result()

    if args.output == 'cli':
        display_cliresult()
    elif args.output == 'json':
        pprint.pprint(result)
        #print(json.dumps(result))
    else:
        print('')
