#!/usr/bin/env python3

import subprocess, json, sys
import requests
import re
import logging as log
import argparse
import os
from datetime import datetime

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

DOCKER_TOKEN=''

def checkImage_quayio(image, imageID):
    '''
    https://quay.io/api/v1/repository/jetstack/cert-manager-webhook/tag/
    https://quay.io/api/v1/repository/jetstack/cert-manager-webhook/tag/?limit=100&page=4&onlyActiveTags=true
    docker-pullable://quay.io/jetstack/cert-manager-controller@sha256:916ad11088651e28923fa6891ac5c27790ba33f6dcc8ca34f223afa6b55f7b54
    '''
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
    print("Image last_modified: {}".format(last_modified))

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
                    print(OKGREEN+'======> OK '+ENDC)
                else:
                    print(FAIL+'======> UPDATE '+ENDC)
                    print('remote: '+image['digest'])
                    print('local : '+digest)

def checkImage_dockerhub(image, imageID, container_last_started):

    [(repository,digest)]  = re.findall(r'docker-pullable://([\w\/-]+)@(sha256:\w+)', imageID)

    [(repository,tag)] = re.findall(r'([\w\/-]+):([\w\.-]+)', image)

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

    if 'last_updated' in remoteimage:
        print("Image last_updated  : {}".format(remoteimage['last_updated']))
        image_last_updated = datetime.strptime(remoteimage['last_updated'], "%Y-%m-%dT%H:%M:%S.%fZ")
        is_latestimage = image_last_updated < container_last_started

    if 'images' in remoteimage:
        for image in remoteimage['images']:
            if image['architecture'] == 'amd64' and image['os'] == 'linux':
                if digest == image['digest'] or is_latestimage:
                    print(OKGREEN+'======> OK '+ENDC)
                else:
                    print(FAIL+'======> UPDATE '+ENDC)
                    print('remote: '+image['digest'])
                    print('local : '+digest)
                    

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

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', required=False, help="increase output verbosity")
    parser.add_argument("-n", "--namespaces", required=False, help="Path to configfile")

    args = parser.parse_args()
    if args.verbose:
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.DEBUG)

    namespacesWhitelist = []
    if args.namespaces:
        namespacesWhitelist = args.namespaces.split(',')

    login_dockerub()
    
    namespaces = json.loads(subprocess.run(["kubectl", "get", "namespaces", "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))

    for namespace in namespaces['items']:
        nsName=namespace['metadata']['name']
        nsUid=namespace['metadata']['uid']
        nsCreationTimestamp=namespace['metadata']['creationTimestamp']

        if namespacesWhitelist and nsName not in namespacesWhitelist: 
            continue

        print("Namespace: {} ------------------------------".format(nsName))
        log.debug("Namespace UID: {}".format(nsUid))
        log.debug("Namespace creation: {}".format(nsCreationTimestamp))
        print("")
        
        pods = json.loads(subprocess.run(["kubectl", "get", "pods", "-n", nsName, "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        for pod in pods['items']:
            print("Pod name: {}".format(pod['metadata']['name']))
            log.debug("Pod creationTimestamp: {}".format(pod['metadata']['creationTimestamp']))
            log.debug("Pod UID: {}".format(pod['metadata']['uid']))
            for containerStatus in pod['status']['containerStatuses']:
                print("Container image: {}".format(containerStatus['image']))
                log.debug("Container imageID: {}".format(containerStatus['imageID']))
                log.debug("Container name: {}".format(containerStatus['name']))

                if 'running' in containerStatus['state']:
                    print("Container started at: {}".format(containerStatus['state']['running']['startedAt']))
                    container_last_started = datetime.strptime(containerStatus['state']['running']['startedAt'], "%Y-%m-%dT%H:%M:%SZ")
                
                if re.search(r'gcr.io',containerStatus['image']):
                    log.debug("repository: gcr.io")
                elif re.search(r'quay.io',containerStatus['image']):
                    log.debug("repository: quay.io")
                    checkImage_quayio(containerStatus['image'], containerStatus['imageID'])
                else:
                    checkImage_dockerhub(containerStatus['image'], containerStatus['imageID'], container_last_started)
            
                print("")