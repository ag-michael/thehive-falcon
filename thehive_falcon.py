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
import re

import pyfalcon


class ES:
    def __init__(self, config, logger):
        import elasticsearch
        self.es = elasticsearch.Elasticsearch(hosts=config["hosts"])
        self.index_name = config["index"]
        self.lh = logger
        self.doctype = config["doctype"]

    def index(self, data):
        try:
            self.es.index(index=self.index_name, doc_type=self.doctype, id=id)
        except Exception as e:
            self.lh.exception("Elasticsearch index error:"+str(e))


class TheHiveProcessor:
    def __init__(self, config, logh):
        self.lh = logh
        self.conf = config
        self.ts = int(time.time())-3600
        self.whitelist = []
        self.blacklist = []
        if self.conf["email_alerts"]:
            from smtplib import SMTP
            from email.mime.text import MIMEText
            self.smtp = SMTP
            self.mimetext = MIMEText

        self.loadwhitelist(self.conf["whitelist_config"])
        self.loadblacklist(self.conf["blacklist_config"])

    def email_alert(self, title, event):
        if not self.conf["email_alerts"]:
            return
        notify = self.conf["email_notify"]
        server = self.conf["email_server"]
        emailmsg = "<h3>"+title+"</h3><br><pre>" + \
            json.dumps(event, indent=4, sort_keys=True)+"</pre>"
        try:
            email = self.mimetext(emailmsg, 'html')
            email['Subject'] = title
            S = self.smtp(server)
            for recipient in notify:
                S.sendmail(self.conf["email_from"],
                           recipient, email.as_string())
                self.lh.info("Sent email notification to: "+recipient)
        except Exception as e:
            self.lh.exception("Email notification exception:"+str(e))

    def loadwhitelist(self, wlconfig):
        wljson = {}
        with open(wlconfig) as f:
            wljson = json.loads(f.read())
        if "whitelist" in wljson:
            self.whitelist = wljson["whitelist"]
            for i in range(0, len(self.whitelist)):
                #self.lh.debug("Processing whitelist item:"+self.whitelist[i]["name"])
                if not "selectors" in self.whitelist[i]:
                    self.whitelist[i]["selector"] = {}
                else:
                    selectors = self.whitelist[i]["selectors"]
                    for selector in selectors:
                        for j in range(len(selectors[selector])):
                            if "regex" == selectors[selector][j]["type"]:
                                # re.compile(selectors[selector][j]["value"])
                                self.whitelist[i]["selectors"][selector][j]["value"] = selectors[selector][j]["value"]
                            elif "file" == selectors[selector][j]["type"]:
                                items = set()
                                with open(selectors[selector][j]["value"]) as f:
                                    for line in f.read().splitlines():
                                        if not line.strip().startswith("#"):
                                            items.add(line.strip().lower())
                                self.whitelist[i]["selectors"][selector][j]["value"] = list(
                                    items)

    def loadblacklist(self, blconfig):
        bljson = {}
        with open(blconfig) as f:
            bljson = json.loads(f.read())
        if "blacklist" in bljson:
            self.blacklist = bljson["blacklist"]
            for i in range(0, len(self.blacklist)):
                #self.lh.debug("Processing blacklist item:"+self.blacklist[i]["name"])
                if not "selectors" in self.blacklist[i]:
                    self.blacklist[i]["selector"] = {}
                else:
                    selectors = self.blacklist[i]["selectors"]
                    for selector in selectors:
                        for j in range(len(selectors[selector])):
                            if "regex" == selectors[selector][j]["type"]:
                                # re.compile(selectors[selector][j]["value"])
                                self.blacklist[i]["selectors"][selector][j]["value"] = selectors[selector][j]["value"]
                            elif "file" == selectors[selector][j]["type"]:
                                items = set()
                                with open(selectors[selector][j]["value"]) as f:
                                    for line in f.read().splitlines():
                                        if not line.strip().startswith("#"):
                                            items.add(line.strip().lower())
                                self.blacklist[i]["selectors"][selector][j]["value"] = list(
                                    items)

    def selectormatch(self, selector_entry, eventval):
        for item in selector_entry:
            matched = False
            if item["type"] == "file":
                for entry in item["value"]:
                    if entry == eventval:
                        matched = True
                        break
                if matched:
                    break
            elif item["type"] == "regex":
                result = re.match(item["value"], eventval)
                if not None is result:
                    matched = True
                    break
            else:
                if item["value"] == eventval:
                    matched = True
                    break
        if not matched:
            # print "Selector "+str(selector_entry)+" did not match value "+eventval
            return False
        # print "Selector "+str(selector_entry)+" matched value "+eventval
        return True

    def blacklisted(self, event):
        try:
            for blitem in self.blacklist:
                match = False
                for selector in blitem["selectors"]:
                    if not selector in event:
                        break
                    match = self.selectormatch(
                        blitem["selectors"][selector], event[selector])
                    if not match:
                        break
                if match:
                    self.lh.info("Blacklist item matched:"+blitem["name"])
                    if "severity" in blitem:
                        event["SeverityName"] = blitem["severity"]
                    return True
            return False
        except Exception as e:
            self.lh.exception("Blacklist item match error:"+str(e))
            return False
        return False

    def whitelisted(self, event):
        try:
            for wlitem in self.whitelist:
                match = False
                for selector in wlitem["selectors"]:
                    if not selector in event:
                        break
                    match = self.selectormatch(
                        wlitem["selectors"][selector], event[selector])
                    if not match:
                        break
                if match:
                    self.lh.info("Whitelist item matched:"+wlitem["name"])
                    return True
            return False
        except Exception as e:
            self.lh.exception("Whitelist item match error:"+str(e))
            return False
        return False

    def thehive_alert(self, alert):
        authheader = {'Content-Type': 'application/json',
                      'Authorization': 'Bearer '+self.conf['thehiveapi']}
        results = requests.post(self.conf['thehiveurl'], headers=authheader, data=json.dumps(
            alert), verify=self.conf['Verify_SSL'])
        if results.status_code > 199 and results.status_code < 300:
            self.lh.debug("Created alert:"+alert["title"])
        else:
            self.lh.debug("Alert creation error:" +
                          str(results.status_code)+"\n"+results.text)

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
        self.loadwhitelist(self.conf["whitelist_config"])
        self.loadblacklist(self.conf["blacklist_config"])
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

                title = "[Falcon Host Detection - "+event["Technique"]+" via "+event["Tactic"] + \
                    " on "+event["ComputerName"]+"/" + \
                        event["UserName"]+"] "+event['DetectDescription']

                if not self.blacklisted(event):
                    if self.whitelisted(event):
                        self.lh.info(
                            "Whitelisted detection will be dropped:"+title)
                        return
                else:
                    self.lh.info("Blacklisted event:"+title)

                pretty_time = datetime.datetime.fromtimestamp(
                    time.time()).strftime('%Y-%m-%d %H:%M:%S')

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
                    self.email_alert(title, event)
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
