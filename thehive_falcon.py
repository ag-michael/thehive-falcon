#!/bin/python2
# -*- coding: utf-8 -*-
import sys
import time
import datetime
import calendar
import json
import logging
import requests
import traceback

import pyfalcon


class TheHiveProcessor:
    def __init__(self, config, logh):
        self.lh = logh
        self.conf = config
        self.ts = int(time.time())-3600

    def thehive_alert(self, alert):
        authheader = {'Content-Type': 'application/json',
                      'Authorization': 'Bearer '+self.conf['thehiveapi']}
        results = requests.post(self.conf['thehiveurl'], headers=authheader, data=json.dumps(
            alert), verify=self.conf['Verify_SSL'])
        if results.status_code == 200:
            self.lh.debug("Created alert:"+alert["title"])
        else:
            self.lh.debug("Alert creation error:\n"+results.text)

    def caseTemplate(self, event):
        return self.conf['defaultCaseTemplate']

    def parse_artifacts(self, event):
        artifacts = []
        iocmap = {"domain": "domain", "ip": "ip", "filename": "filename",
                  "command_line": "commandline", "hash_sha256": "hash", "registry_key": "registry"}
        if 'observable_map' in self.conf:
            for o in self.conf['observable_map']:
                if o in event:
                    artifact = self.conf['observable_map'][o]
                    artifact['data'] = event[o]
                    artifacts.append(artifact)
        if "IOCType" in event and iocmap[event["IOCType"]]:
            artifact = {"dataType": iocmap[event["IOCType"]],
                        "message": "Detection IOC", "data": event["IOCValue"]}
            artifacts.append(artifact)
        return artifacts

    def processor(self, stream_data):
        if stream_data['metadata']['eventType'] == 'DetectionSummaryEvent':
            event = stream_data['event']
            event_time = calendar.timegm(time.gmtime(
                (stream_data['metadata']['eventCreationTime']/1000)))
            tags = ["Crowdstrike Falcon"]
            if "tag_fields" in self.conf:
                for tag in self.conf["tag_fields"]:
                    if tag in event:
                        tags.append(event[tag])
            if event_time > self.ts:
                alert_message = ''
                pretty_time = datetime.datetime.fromtimestamp(
                    time.time()).strftime('%Y-%m-%d %H:%M:%S')
                title = "[Falcon Host Detection - "+event["Technique"]+" via "+event["Tactic"]+" on " + \
                    event["ComputerName"]+"/"+event["UserName"]+"] " + \
                        event['DetectDescription']  # +" ("+pretty_time+")"
                sev = 3
                if "medium" == event["SeverityName"].lower():
                    sev = 2
                elif event["SeverityName"].lower() in ["critical", "high"]:
                    sev = 3
                else:
                    sev = 1
                alert = {
                    "title": title,
                    "description": "```\n"+json.dumps(event, indent=4, sort_keys=True)+"\n```",
                    "type": event['DetectName'],
                    "source": event['SensorId']+" "+pretty_time,
                    "sourceRef": event['FalconHostLink'],
                    "severity": sev,
                    "tlp": 3,
                    "tags": tags,
                    "artifacts": self.parse_artifacts(event),
                    "caseTemplate": self.caseTemplate(event)
                }
                try:
                    self.thehive_alert(alert)
                    self.lh.info("Created new alert:"+alert['title'])
                except Exception as e:
                    self.lh.exception("Error while creating an alert"+str(e))
            else:
                title = "[Falcon Host Detection - "+event["Tactic"]+"/"+event["Technique"]+"] " + \
                    event["ComputerName"]+"/"+event["UserName"] + \
                        " - "+event['DetectDescription']
                self.lh.debug(str(event_time)+"/" +
                              str(self.ts)+" Ignoring:"+title)

#		else:
#			print(".")
#			self.lh.debug("Discarding unsupported stream data:\n"+json.dumps(stream_data,indent=4,sort_keys=True))


def main():
    falcon_config = thehive_config = {}
    with open(sys.argv[1]) as f:
        falcon_config = json.loads(f.read())
    with open(sys.argv[2]) as f:
        thehive_config = json.loads(f.read())
    lh = logging.getLogger('TheHive-Falcon')
    lh.setLevel(logging.DEBUG)
    logging.basicConfig(format='TheHive-Falcon: %(asctime)-15s  %(message)s')
    lh.info("Starting Falcon streaming api integration script for TheHive...")

    thehive_processor = TheHiveProcessor(thehive_config, lh)

    def processor(stream_data):
        thehive_processor.processor(stream_data)

    falcon_api = pyfalcon.FalconStreamingAPI(falcon_config, processor)

    while True:
        lh.info("Connecting to the Falcon streaming api.")
        try:
            if falcon_api.connect():
                lh.info("Connected to the Falcon streaming api")
                falcon_api.streamData()
                lh.info("Sleeping until expiry time, which is after " +
                        str(falcon_api.sleeptime)+" seconds.")
                time.sleep(falcon_api.sleeptime)
            if falcon_api.reconnect:
                time.sleep(4)
            else:
                time.sleep(falcon_api.sleeptime)
        except Exception as e:
            lh.exception("Falcon steaming api exception:"+str(e))
            traceback.print_exc()
            time.sleep(3)
            continue


if __name__ == "__main__":
    reload(sys)
    sys.setdefaultencoding("utf-8")
    main()
