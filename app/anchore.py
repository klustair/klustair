import subprocess
import json
import sys
import logging as log
import time
import pprint
class Anchore: 
    def __init__(self):
        print("INFO: Start Anchore analysis")

    def submitImagesToAnchore(self, uniqueImagesList):
        print('INFO: Submit images to Anchore')
        for image in uniqueImagesList.values():
            json.loads(subprocess.run(["anchore-cli", "--json", "image", "add", image['fulltag']], stdout=subprocess.PIPE).stdout.decode('utf-8'))
            log.debug("Submitted Image: {}".format(image['fulltag']))

    def getImageDetailsList(self, uniqueImagesList):
        print('INFO: Load imagedetails')
        for imageUid, image in uniqueImagesList.items():
            log.debug("Load Image: {}".format(uniqueImagesList[imageUid]['fulltag']))
            imagedetails = json.loads(subprocess.run(["anchore-cli", "--json", "image", "get", uniqueImagesList[imageUid]['fulltag']], stdout=subprocess.PIPE).stdout.decode('utf-8'))[0]
            
            uniqueImagesList[imageUid] = {
                'image_b64': image['image_b64'],
                'uid': image['uid'],
                'anchore_imageid': imagedetails['image_detail'][0]['imageId'],
                'analyzed_at': imagedetails['analyzed_at'],
                'created_at': imagedetails['created_at'],
                'fulltag': imagedetails['image_detail'][0]['fulltag'],
                'image_digest': imagedetails['imageDigest'],
                'arch': imagedetails['image_content']['metadata']['arch'],
                'distro': imagedetails['image_content']['metadata']['distro'],
                'distro_version': imagedetails['image_content']['metadata']['distro_version'],
                'image_size': imagedetails['image_content']['metadata']['image_size'],
                'layer_count': imagedetails['image_content']['metadata']['layer_count'],
                'registry': imagedetails['image_detail'][0]['registry'],
                'repo': imagedetails['image_detail'][0]['repo'],
                'dockerfile': imagedetails['image_detail'][0]['dockerfile']
            }
        return uniqueImagesList

    def getAnchoreVulnerabilities(self, imageDetailsList, reportsummary):
        print('INFO: Load Vulnerabilities')
        imageVulnListAnchore = {}
        imageVulnSummaryAnchore = {}
        for image in imageDetailsList.values():
            
            reportsummary['images'] += 1

            log.debug("Load Vuln: {}".format(image['fulltag']))
            vulnsum = {
                'Critical': {
                    'severity': 0,
                    'total': 0,
                    'fixed': 0
                },
                'High': {
                    'severity': 1,
                    'total': 0,
                    'fixed': 0
                },
                'Medium': {
                    'severity': 2,
                    'total': 0,
                    'fixed': 0
                },
                'Low': {
                    'severity': 3,
                    'total': 0,
                    'fixed': 0
                },
                'Negligible': {
                    'severity': 4,
                    'total': 0,
                    'fixed': 0
                },
                'Unknown': {
                    'severity': 5,
                    'total': 0,
                    'fixed': 0
                }
            }

            imageVuln = json.loads(subprocess.run(["anchore-cli", "--json", "image", "vuln", image['fulltag'], 'all'], stdout=subprocess.PIPE).stdout.decode('utf-8'))
            
            for vulnerability in imageVuln['vulnerabilities']:
                vulnsum[vulnerability['severity']]['total'] += 1
                reportsummary['vuln_total'] += 1
                reportsummary['vuln_'+vulnerability['severity'].lower()] += 1
                if vulnerability['fix'] != 'None':
                    vulnsum[vulnerability['severity']]['fixed'] += 1
                    reportsummary['vuln_fixed'] += 1

            image_uid = image['uid']
            imageVulnListAnchore[image_uid] = imageVuln['vulnerabilities']
            imageVulnSummaryAnchore[image_uid] = vulnsum
        
        return imageVulnListAnchore, imageVulnSummaryAnchore

    def awaitAnalysis(self, ):
        try:
            allAnalyzed = False
            while allAnalyzed == False:
                time.sleep(3)
                anchoreSyncStatus = json.loads(subprocess.run(["anchore-cli", "--json", "image", "list"], stdout=subprocess.PIPE).stdout.decode('utf-8'))

                # Check if all images are analyzed
                for status in anchoreSyncStatus:
                    if status['analysis_status'] == 'analyzing':
                        print('INFO: waiting for image {0} to be analysed'.format(status['image_detail'][0]['fulltag']))
                        allAnalyzed = False
                        break
                    else: 
                        allAnalyzed = True

        except (KeyboardInterrupt, SystemExit):
            print("ABORT: Analysis aborted. No data was saved. ")
            sys.exit(0)
        #except:
        #    print("ERROR: Analysis aborted. No data was saved. ")
        #    sys.exit(0)