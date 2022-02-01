import os
import json
import urllib.request
import urllib.parse

import requests
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask,request,jsonify
from bson.objectid import ObjectId
from requests_ntlm import HttpNtlmAuth
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from datetime import datetime
from pymongo import MongoClient
from lib import utility as util
# import uploadListener as ul
import uuid
from config import was,environment as env
import psutil
import time
from zapv2 import ZAPv2
from urllib import parse
import urllib.parse as urlparse
from urllib.parse import parse_qs
import requests
import sys
import subprocess
from pprint import pprint
from copy import deepcopy
import lib.framework as fw


class CrawlerUtils:

    def __init__(self,applicationId):
        self.applicationId=applicationId
        self.mongoClient=MongoClient(host=was.was["database"])
        #'was_db'=was.environment["current_db"]
        self.dbConn=self.mongoClient['was_db']
        self.ZAPPortsTable=self.dbConn['zap_ports']
        self.urlStoreTempTable=self.dbConn['temp_url_store']
        self.finalUrlStoreTempTable=self.dbConn['url_store']
        self.applicationInfoTable=self.dbConn['applications']
        self.log=util.Crawl_Log()
        self.redis=util.Database().Redis()
        portInfo=self.ZAPPortsTable.find({"applicationId":applicationId}).limit(1)
        zapDetails=''
        for data in portInfo:
            if "_id" in data:
                zapDetails=data
                break

        if len(zapDetails)>0:
            self.ZapAPIKey=zapDetails['applicationAPIKey']
            self.ZapIP=zapDetails['zapIP']
            self.ZapPort=zapDetails['zapPort']
            self.processId=zapDetails['processId']
            self.scanId=zapDetails['scanId']
            self.target=zapDetails['applicationURL']
            # self.userInfo = zapDetails['userInfo']
        else:
            pass
            # return jsonify({'data': {'code': 404, 'status': 'error', 'message': 'Unable to fetch Application Information.'}})

        # self.ZAPHeaders = {'Accept': 'application/json', 'X-ZAP-API-Key': '{0}'.format(self.ZapAPIKey)}

    # This funtion is to Pause ZAP / Crawl Operation

    # def pauseCrawl(self):
    #     try:
    #         pauseZapTrigger = requests.get('http://{0}:{1}/JSON/spider/action/pause/'.format(self.ZapIP, self.ZapPort),
    #                                        params={'scanId': self.scanId}, headers=self.ZAPHeaders)
    #         if (pauseZapTrigger.status_code == 200):
    #             return jsonify({'data': {'code': pauseZapTrigger.status_code, 'status': 'success',
    #                                      'message': 'Crawl Operation Paused Successfully.'}})
    #         else:
    #             return jsonify({'data': {'code': pauseZapTrigger.status_code, 'status': 'error',
    #                                      'message': 'Crawl Operation Could not be Paused.'}})
    #     except Exception as e:
    #         return jsonify({'data': {'code': 2025, 'status': 'error',
    #                                  'message': 'Unable to Process Crawl : Pause Crawl.', 'exception': e}})

    # def resumeCrawl(self):
    #     print("Resuming crawl operation")
    #     return 0

    #     # This funtion is to Stop ZAP / Crawl Operation

    # def stopCrawl(self):
    #     try:
    #         stopZapTrigger = requests.get('http://{0}:{1}/JSON/spider/action/stop/'.format(self.ZapIP, self.ZapPort),
    #                                       params={}, headers=self.ZAPHeaders)
    #         if (stopZapTrigger.status_code == 200):
    #             if len(self.z) >= 1:
    #                 zapKill = ("kill {0}").format(self.z)
    #                 subprocess.Popen([zapKill], shell=True)
    #             self.ZAPPortsTable.update_one({"_id": self.ZapAPIKey}, {
    #                 "$set": {"portStatus": "active", "applicationName": 'none', "applicationId": 'none',
    #                          "applicationAPIKey": 'none', "applicationURL": 'none', "scanId": 'none',
    #                          "processId": 'none', "updated_dt": datetime.now().isoformat()}})

    #         self.log.info("Crawl Operation Stoped Successfully.")
    #         return jsonify({'data': { 'status': 'success',
    #                                      'message': 'Crawl Operation Stoped Successfully.'}})
    #     except Exception as e:
    #         return jsonify({'data': {'code': 2026, 'status': 'error',
    #                                  'message': 'Unable to Process Crawl : Stop Crawl.', 'exception': e}})

    def resources(self):
        # Getting % usage of virtual_memory ( 3rd field)
        # print('Resource Check')
        memory=psutil.virtual_memory()[2]
        disk=psutil.disk_usage('/')
        # CPU usage percentage
        cpu_percentage=psutil.cpu_percent(interval=1)
        print(cpu_percentage)
        print(memory)
        print(disk)
        if memory>50 and disk.percent<50 and cpu_percentage<20:
            print("Resource check done")


# class Log:
#     def log(self):
#         # logging.basicConfig(filename='crawl.log', format='%(asctime)s | %(levelname)s | %(name)s | %(message)s', level=logging.DEBUG, force=True)
#         logging.basicConfig(filename='crawl.log', filemode='w')
#         logger = logging.getLogger()
#         return logger


class Crawler:
    def __init__(self,applicationId,applicationName,applicationURL,crawlType,usersInfo):
        # self.log = logging.getLogger()
        # fhandler = logging.FileHandler(filename=f'/home/virsec/was/artefacts/traces/crawl.log', mode='a')
        # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # fhandler.setFormatter(formatter)
        # self.log.addHandler(fhandler)
        # self.log.setLevel(logging.DEBUG)
        self.ZapDirectory=was.was["zap"]
        self.crawlType=crawlType
        self.applicationName=applicationName
        self.applicationURL=applicationURL
        self.applicationId=applicationId
        self.usersInfo=usersInfo
        self.appUserName=''
        self.appPassword=''
        self.appAuthenticationType=''
        self.appAuthLogin=''
        self.appAuthLogout=''
        self.appDomain=''
        self.appHostName=''
        self.processId=''
        self.ZapAPIKey=''
        self.ZapIP='0.0.0.0'
        self.ZapPort=''
        self.__scanId=0
        self.isInteractiveAuth=False
        self.ZAPHeaders={'Accept':'application/json','X-ZAP-API-Key':'{0}'.format(self.ZapAPIKey)}

        self.APGIP='127.0.0.1'
        self.APGURL=f'http://{self.APGIP}/test/index.html'
        self.mongoClient=MongoClient(host=was.was["database"])
        #'was_db'=was.environment["current_db"]
        self.dbConn=self.mongoClient['was_db']
        self.vaultTable=self.dbConn['vault']
        self.ZAPPortsTable=self.dbConn['zap_ports']
        self.credentialsTable=self.dbConn['credentials']
        self.urlStoreTable=self.dbConn['uri_store']
        self.tempUrlStoreTable=self.dbConn['temp_url_store']
        self.applicationTable=self.dbConn['applications']
        self.log=util.Crawl_Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()
        # self.target = 'https://public-firing-range.appspot.com'
        self.target=applicationURL
        self.context_name="new_context"
        self.crawl_id=util.Authentication().generate_random_string(length=5)
        self.service_ip_map={}
        self.scan_ids=[]

    # def __init__(self, applicationId, applicationName, applicationURL, crawlType, usersInfo):

    #     self.log = logging.getLogger()
    #     log_file=os.path.join(was.environment["logging"]["log_location"],was.environment["logging"]["crawl_log"]["name"])
    #     max_size=(int(was.environment["logging"]["crawl_log"]["size_limit"]) * 1024 * 1024)
    #     backup_count=int(was.environment["logging"]["crawl_log"]["backup_count"])
    #     self.log.setLevel(logging.DEBUG)
    #     fhandler = RotatingFileHandler(filename=log_file,maxBytes=max_size,mode='a',backupCount=backup_count)
    #     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #     fhandler.setFormatter(formatter)
    #     self.log.addHandler(fhandler)

    #     self.ZapDirectory = '/home/virsec/ZAP_2.10.0/zap-2.10.0.jar'
    #     self.crawlType = crawlType
    #     self.applicationName = applicationName
    #     self.applicationURL = applicationURL
    #     self.applicationId = applicationId
    #     self.usersInfo = usersInfo
    #     self.appUserName = ''
    #     self.appPassword = ''
    #     self.appAuthenticationType = ''
    #     self.appAuthLogin = ''
    #     self.appAuthLogout = ''
    #     self.appDomain = ''
    #     self.appHostName = ''
    #     self.processId = ''
    #     self.ZapAPIKey = ''
    #     self.ZapIP = '0.0.0.0'
    #     self.ZapPort = ''
    #     self.scanId = 0
    #     self.isInteractiveAuth=False
    #     self.ZAPHeaders = {'Accept': 'application/json', 'X-ZAP-API-Key': '{0}'.format(self.ZapAPIKey)}

    #     self.APGIP = '127.0.0.1'
    #     self.APGURL = f'http://{self.APGIP}/test/index.html'
    #     self.mongoClient = MongoClient(host=was.was["database"])
    #     self.dbConn = self.mongoClient['was_db']
    #     self.vaultTable = self.dbConn['vault']
    #     self.ZAPPortsTable = self.dbConn['zap_ports']
    #     self.credentialsTable = self.dbConn['credentials']
    #     self.urlStoreTable = self.dbConn['uri_store']
    #     self.tempUrlStoreTable = self.dbConn['temp_url_store']
    #     self.applicationTable = self.dbConn['applications']
    #     # self.log = util.Log()
    #     self.redis = util.Database().Redis()
    #     self.mongo = util.Database().Mongo()
    #     # self.target = 'https://public-firing-range.appspot.com'
    #     self.target = applicationURL

    def fetchAvailableZapPort(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            portInfo=self.ZAPPortsTable.find({"portStatus":"active"}).limit(1)
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            zapDetails=''

            for data in portInfo:
                if "_id" in data:
                    zapDetails=data
                    break

            if len(zapDetails)>0:
                self.ZapAPIKey=str(zapDetails['zapPort'])  # '12345'  # zapDetails['_id']
                self.ZapIP=zapDetails['zapIP']
                self.ZapPort=zapDetails['zapPort']

                self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                    "$set":{"portStatus":"busy","applicationURL":self.applicationURL,"userInfo":self.usersInfo,
                        "applicationId":self.applicationId,"updated_dt":datetime.now().isoformat(),
                        "applicationName":self.applicationName,"applicationAPIKey":self.ZapAPIKey}})
                self.log.info("Crawl: zap details updated successfully in zapporttable")
            else:
                self.log.critical("Crawl Aborted! Zap ports not found")
                return jsonify({'data':{'code':2028,'status':'error',
                    'message':'Unable to Process Crawl : No ZAP Ports are Available.'}})

        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            self.log.critical(f"Crawl: Zap port allocation raised exception:{e}")
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}) Zap port is not available"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)

            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})

    def fetchZAPProcessId(self,ZapAPIKey):
        try:
            self.ZapAPIKey=ZapAPIKey

            self.log.info(f"Fetching ZAP process ID with key {self.ZapAPIKey}")
            zapDataCmd=("ps -aux | grep ZAP | grep -v grep")
            execGrep=subprocess.Popen(zapDataCmd,shell=True,stdout=subprocess.PIPE)
            self.processId=execGrep.communicate()[0].decode('utf-8')
            if self.processId:
                self.log.info(f"ZAP process ID: {(self.processId.split())[1]}")
                return (self.processId.split())[1]
            else:
                return None
        except Exception as e:
            self.log.critical('Crawl: Exception raised when fetching zap process id: f{e}')
            sys.exit(2029)

    def startZAP(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.log.info(f"Starting ZAP with key: {self.ZapAPIKey}")
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            portNumRaw=self.fetchZAPProcessId(self.ZapAPIKey)
            if portNumRaw is None:
                self.zapTrigger=(
                    "java -jar {0} -daemon -host {1} -port {2} -config api.key='{3}' -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true > zap.txt ").format(
                    self.ZapDirectory,self.ZapIP,self.ZapPort,self.ZapAPIKey)
                subprocess.Popen([self.zapTrigger],shell=True)
                self.log.info("ZAP started successfully for the first time")
                self.log.info("self.zapTrigger",self.zapTrigger)
            elif len(portNumRaw)>=1:
                self.zapTrigger=(
                    "java -jar {0} -daemon -host {1} -port {2} -config api.key={3} > zap.txt ").format(
                    self.ZapDirectory,self.ZapIP,self.ZapPort,self.ZapAPIKey)
                subprocess.Popen([self.zapTrigger],shell=True)
                self.log.info('self.zapTrigger',self.zapTrigger)
                self.log.info("ZAP started successfully")
        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.log.error(e)

            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            self.log.info("zap details updated")
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}). Unable to start ZAP"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error','message':'Unable to Process Crawl : StartZAP.',
                'exception':e}})

    def validateZAPAPI(self):
        try:
            print("validateZAPAPI")
            self.log.info("validating ZAP API")
            tempURL=("http://{0}:{1}/JSON/context/view/contextList/").format(self.ZapIP,self.ZapPort)
            print(tempURL)

            tempResponse=requests.get(tempURL)
            print(tempResponse)
            if tempResponse.status_code==200:
                print("Success: Valid ZAP API Key.")
            else:
                return ({'data':{'code':2039,'status':'error',
                    'message':'Unable to Process Crawl : Invalid ZAP API Key.'}})

        except Exception as e:
            print({'data':{'code':2038,'status':'error',
                'message':'Unable to Process Crawl : Error in Validating ZAP API Key.',
                'exception':e}})

    def get_query_params(self,url):
        dict={
            "exercisable_parameters":[],
            "parameters":{}
        }
        parsed=urlparse.urlparse(url)
        query_obj=parse_qs(parsed.query,keep_blank_values=True)
        for d in query_obj:
            if "." in d:
                continue
            else:
                dict['exercisable_parameters'].append(d)
                dict['parameters'][d]="".join(query_obj[d])
        return dict

    def crawlPercentage(self):
        cache=self.redis.connect(host=was.was['cache'])
        while int(self.zap.spider.status(self.scanID))<100:
            # Poll the status until it completes
            self.log.info("Spider progress %: {}".format(self.zap.spider.status(self.scanID)))
            print('Spider progress %: {}'.format(self.zap.spider.status(self.scanID)))
            crawl_percent=self.zap.spider.status(self.scanID)
            cache.hset('crawl',self.applicationId,{'application_id':f'{self.applicationId}',
                'crawl_state':'in_progress','crawl_progress':crawl_percent})
            time.sleep(1)

        if crawl_percent==100:
            cache.hset('crawl',self.applicationId,{'application_id':f'{self.applicationId}',
                'crawl_state':'crawl_completed',
                'crawl_progress':crawl_percent})

            self.ZAPPortsTable.update_one({"_id":self.ZapAPIKey},{
                "$set":{"portStatus":"active","applicationName":'none',"applicationId":'none',
                    "applicationAPIKey":'none',"applicationURL":'none',"scanId":'none',
                    "processId":'none',"updated_dt":datetime.now().isoformat()}})

    def crawlApplication(self):
        def get_header_dict(header_str):
            arr=header_str.strip().splitlines()
            header_dict={}
            for val in arr:
                if all([x not in val for x in ['POST','GET']]):
                    check_header_key=val.split(":",1)[0]
                    if "." in check_header_key:
                        continue
                    else:
                        header_dict[val.split(":",1)[0]]=val.split(":",1)[1]
            return header_dict

        try:
            # from config import was
            cache_channel=self.redis.connect(host=was.was['cache'])
            # cache_channel = self.redis.connect(host='localhost')
            #'was_db'=was.environment["current_db"]
            self.dbConn=self.mongoClient['was_db']
            self.ZAPPortsTable=self.dbConn['zap_ports']
            self.urlStoreTempTable=self.dbConn['temp_url_store']
            self.finalUrlStoreTempTable=self.dbConn['url_store']
            self.applicationInfoTable=self.dbConn['applications']
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            # self.homepageUrl=self.finalUrlStoreTempTable.find()

            self.zap=ZAPv2(apikey=self.ZapAPIKey,proxies={
                'http':f'http://{str(self.ZapIP)}:{str(self.ZapPort)}',  # 'http': f'http://{ZapIP}:{ZapPort}',
                'https':f'http://{str(self.ZapIP)}:{str(self.ZapPort)}'
            })

            # zap.context.import_context('${workspace}/sbir-security/sbir.context', apikey=self.ZapAPIKey)
            time.sleep(2)
            if self.isInteractiveAuth:
                scanid=self.crawl_for_interactive_auth()
                if scanid!=None:
                    self.scanID=scanid
                else:
                    self.crawl_for_non_interactive_auth()
                    #self.scanID = self.zap.spider.scan(self.target, apikey=self.ZapAPIKey)
            else:
                self.crawl_for_non_interactive_auth()
                #self.scanID = self.zap.spider.scan(self.target, apikey=self.ZapAPIKey)
            self.log.info(f"ZAP scan started; scanID {self.scanID}")
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{'scanId':self.scanID}})
            print("zap details updated")
            cache_map={}
            cache_map['application_id']=self.applicationId
            manual_crawl_list=Manual(applicationId=self.applicationId).get_manual_crawls()
            self.perform_zap_scan_for_manual_urls(crawl_list=manual_crawl_list)
            ######################################
            spider_progress=0
            no_of_scans=0
            scan_data=self.zap.spider.scans
            no_of_scans=len(scan_data)
            while int(spider_progress)<100:
                temp_percentage=0
                #no_of_scans=0
                for scan_d in self.zap.spider.scans:
                    # if int(scan_d["progress"]) != 100:
                    #     no_of_scans+=1
                    temp_percentage+=int(scan_d["progress"])
                spider_progress=round(temp_percentage/int(no_of_scans),1)
                if spider_progress < 99:
                    self.log.info("Spider progress %: {}".format(spider_progress))
                    print('Spider progress %: {}'.format(spider_progress))
                    time.sleep(1)
                    cache_map['crawl_state']='in_progress'
                    cache_map['crawl_progress']=spider_progress
                    cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})

            ######################################
            # while int(self.zap.spider.status(self.scanID))<100:
            #     # Poll the status until it completes
            #     spider_progress=self.zap.spider.status(self.scanID)
            #     self.log.info("Spider progress %: {}".format(spider_progress))
            #     print('Spider progress %: {}'.format(spider_progress))
            #     time.sleep(1)
            #     cache_map['crawl_state']='in_progress'
            #     cache_map['crawl_progress']=spider_progress
            #     cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})

            #     # cache_map['crawl_state'] = crawl_state
            #     # cache_map['crawl_progress'] = self.zap.spider.status(self.scanID)
            #     # cache_channel.hmset('crawl', {self.application_id: str(cache_map)})
            #     # time.sleep(5)
            total_urls=[]
            for s_id in self.scan_ids:
                total_urls.extend(self.zap.spider.results(s_id))
            self.Url_list=total_urls
            self.header_list=[]
            # TODO handle hostname
            self.hostname=parse.urlparse(self.target).netloc

            # print(zap.spider.full_results(scanID)[0]["urlsInScope"])
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
            count=1
            for s_id in self.scan_ids:
                for data in self.zap.spider.full_results(s_id)[0]["urlsInScope"]:
                    url_id=f"url_{count}"
                    request_type=data['method']
                    attack_url=data['url'].split("?")[0]
                    exercisable_parameters=[]
                    parameters={}
                    header={}
                    b_valid_method=False
                    hostname=parse.urlparse(data['url']).netloc
                    url_info=self.zap.core.messages_by_id(data['messageId'])[0]
                    if (data['method']=='POST'):
                        b_valid_method=True
                        for d in url_info['requestBody'].split("&"):
                            p=d.split("=")
                            if "." in p[0]:
                                continue
                            else:
                                parameters[p[0]]=p[1]
                        exercisable_parameters=list(parameters.keys())
                        header=get_header_dict(url_info['requestHeader'])
                    if (data['method']=='GET'):
                        if data['url'].split(".")[-1:][0] not in was.configuration['exclusion_ext']:
                            b_valid_method=True
                            dict=self.get_query_params(data['url'])
                            parameters=dict['parameters']
                            exercisable_parameters=dict["exercisable_parameters"]
                            header=get_header_dict(url_info['requestHeader'])
                    # print(data)
                    if (b_valid_method):
                        self.header_list.append({
                            "crawl_id":self.crawl_id,
                            "url_id":url_id,
                            "user_agent":user_agent,
                            "requestType":request_type,
                            "attack_url":attack_url,
                            "exercisable_parameters":exercisable_parameters,
                            "parameters":parameters,
                            "hostname":hostname,
                            "header":header
                        })
                    count+=1
        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.log.error(e)
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            print("zap details updated")
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}). Unacepted exception generated at ZAP"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})

    def processTempUrls(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            self.dbConn=self.mongoClient['was_db']
            self.ZAPPortsTable=self.dbConn['zap_ports']
            self.urlStoreTempTable=self.dbConn['temp_url_store']
            self.finalUrlStoreTempTable=self.dbConn['url_store']
            self.applicationInfoTable=self.dbConn['applications']
            # check = self.urlStoreTempTable.find({"hostname": self.hostname})
            attack_urls=[]
            temp_urls=[]
            # for i in check:
            #     attack_urls.append(i['attack_url'])
            self.urlStoreTempTable.delete_many({"crawl_id":self.crawl_id})
            for i in self.header_list:
                # if i['attack_url'] not in attack_urls:
                temp_urls.append(i)

            if len(temp_urls)>=1:
                self.urlStoreTempTable.insert_many(temp_urls)
                print("records added")
                self.log.info("Temp URL Store genarated")


        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            print("zap details updated")
            self.log.error(e)
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}) at time of URL store generation"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})

    def processUrlStore(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.redis=util.Database().Redis()
            self.mongo=util.Database().Mongo()
            self.processTempUrls()
            #'was_db'=was.environment["current_db"]
            self.dbConn=self.mongoClient['was_db']
            self.ZAPPortsTable=self.dbConn['zap_ports']
            self.urlStoreTempTable=self.dbConn['temp_url_store']
            self.finalUrlStoreTempTable=self.dbConn['url_store']
            self.applicationInfoTable=self.dbConn['applications']
            cursor=self.finalUrlStoreTempTable.find({"application_id":self.applicationId}).limit(1)
            tempCursor=self.urlStoreTempTable.find({"crawl_id":self.crawl_id})
            replace=self.applicationInfoTable.find({"application_id":self.applicationId})
            re=list(replace)
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            coll=self.mongo.create_collection(db,'pre_crawl_store')
            burp_xml_doc=self.mongo.find_document(coll,{'application_id':self.applicationId})
            manual_doc=self.mongo.find_document(coll,{'application_id':self.applicationId})
            burp_xml_URLS=[]
            manual_URLS=[]
            duplicate_url = []
            if 'burp_xml' in burp_xml_doc:
                burp_xml=burp_xml_doc['burp_xml']['urls']
                for j in burp_xml:
                    for k,v in j.items():
                        burp_xml_URLS.append(v['attack_url'])

            if 'manual' in manual_doc:
                manual=manual_doc.get('manual',{}).get('urls',{})
                for k,v in manual.items():
                    manual_URLS.append(v)

            url_store=''
            user_info=''
            # userinfo from application table
            for i in re:
                url_store=i['crawl']['url_store']
            #     user_info = i['crawl']['users']
            # print("user_info :",user_info)
            # for user in user_info:
            #     user_id=user['user_id']
            # for y in user_info:
            #     user_id = i['user_id']
            for k,v in self.usersInfo.items():
                user_id=k

            # if replace is enable
            if url_store=='replace':
                self.finalUrlStoreTempTable.update({"application_id":self.applicationId},
                    {"$unset":{f'urls.{user_id}':""}})

            # data in URL_store
            cur=list(cursor)

            # data in temp_url_store
            l1=list(tempCursor)
            # self.log.info("Temp_Urls",l1)
            # print("data in temp:",l1)
            check_urls={}
            attack_urls=[]
            urls_attack=[]
            # self.records={'user_0':{'servicetag1': {}}}
            self.records={}

            # check url key present or not
            for i in cur:
                if 'urls' in i:
                    check_urls=i['urls']

            check_urls=len(check_urls)
            k=0
            self.records[f'{user_id}']={}
            
            for service_name in self.service_ip_map.keys():
                self.records[f'{user_id}'][service_name] = {}
            count=0
            for i in l1:
                i.pop("hostname")
                i.pop("_id")
                url='url_'+str(k)
                # self.records[f'{user_id}']['servicetag1'][f'{url}'] = {}
                # self.records['servicetag1'][f'{url}']={}
                # if i not in burp_xml_URLS:
                
                service_tag=self.get_service_tag_name(url=i["attack_url"])
                if service_tag not in self.records[f'{user_id}'].keys():
                    self.records[f'{user_id}'][service_tag]={}
                self.records[f'{user_id}'][service_tag][f'{url}'] = i
                #     #self.records['servicetag1'][f'{url}'] = i

                #     # records['user_0']['servicetag1'][f'{url}'] = i
                # else:
                #     self.log.info("URL already present")
                k+=1
                count+=1

                # burp_xml Urls added
            # if 'burp_xml' in burp_xml_doc:

            #     for j in burp_xml:
            #         url = 'url_' + str(count)
            #         self.records[f'{user_id}']['servicetag1'][f'{url}'] = j
            #         #self.records['servicetag1'][f'{url}'] = j
            #         count += 1
            if 'manual' in manual_doc:
                for j in manual_URLS:
                    url='url_'+str(count)
                    if 'hostname' in j:
                        j.pop('hostname')
                    j['url_id']=url
                    service_tag=self.get_service_tag_name(url=i["attack_url"])
                    if service_tag not in self.records[f'{user_id}'].keys():
                        self.records[f'{user_id}'][service_tag]={}
                    # self.records[f'{user_id}']['servicetag1'][f'{url}'] = {}
                    # self.records[f'{user_id}']['servicetag1'][f'{url}']['url_id']= url
                    self.records[f'{user_id}'][service_tag][f'{url}'] = j

                    count+=1
            ###########################
            cache_map={}
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='in_progress'
            cache_map['crawl_progress']="99.5"
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            records={}
            records[f'{user_id}']={}
            ###########################
            for service_tag in self.records[user_id].keys():
                urls_to_be_processed={}
                urls_to_be_processed = deepcopy(self.records[f'{user_id}'][service_tag])
                records[f'{user_id}'][service_tag] = self.remove_duplicates(urls_to_be_processed)
            ###########################
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='in_progress'
            cache_map['crawl_progress']="100"
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            ###########################
            #############
            # request_type_repeate=[]
            # keep_urls=[]
            # # duplicate_id={}
            # for ind1,d1 in enumerate(self.records[f'{user_id}']['servicetag1']):
            #     # duplicate_id[d1]={}
            #     for ind2,d2 in enumerate(self.records[f'{user_id}']['servicetag1']):
            #         # ###############
            #         # duplicate_attack_url = False
            #         # duplicate_requestType = False
            #         # duplicate_exercisable_parameters = False
            #         # duplicate_parameters = False
            #         # duplicate_header = False
            #         # if self.records[f'{user_id}']['servicetag1'][d1]['attack_url']== self.records[f'{user_id}']['servicetag1'][d2]['attack_url']:
            #         #     duplicate_attack_url=True
            #         # if self.records[f'{user_id}']['servicetag1'][d1]['requestType']== self.records[f'{user_id}']['servicetag1'][d2]['requestType']:
            #         #     duplicate_requestType=True
            #         # if self.records[f'{user_id}']['servicetag1'][d1]['exercisable_parameters'] == self.records[f'{user_id}']['servicetag1'][d2]['exercisable_parameters']:
            #         #     duplicate_exercisable_parameters=True
            #         # if (all([duplicate_attack_url,duplicate_requestType,duplicate_exercisable_parameters])):
            #         #     duplicate_id[d1].append(d2)
            #         # ###############
            #         if (d1 != d2):
            #             duplicate_attack_url = False
            #             duplicate_requestType = False
            #             duplicate_exercisable_parameters = False
            #             duplicate_parameters = False
            #             duplicate_header = False
            #             if self.records[f'{user_id}']['servicetag1'][d1]['attack_url']== self.records[f'{user_id}']['servicetag1'][d2]['attack_url']:
            #                 if self.records[f'{user_id}']['servicetag1'][d1]['requestType']== self.records[f'{user_id}']['servicetag1'][d2]['requestType']:
            #                     total = len(set(self.records[f'{user_id}']['servicetag1'][d1]['exercisable_parameters']) | set(self.records[f'{user_id}']['servicetag1'][d2]['exercisable_parameters']))
            #                     same_url = len(set(self.records[f'{user_id}']['servicetag1'][d1]['exercisable_parameters']) & set(self.records[f'{user_id}']['servicetag1'][d2]['exercisable_parameters']))
            #                     different = total - same_url
            #                     if different == 0:
            #                         if self.records[f'{user_id}']['servicetag1'][d1]['requestType'] not in request_type_repeate:
            #                             if d1 not in keep_urls:
            #                                 keep_urls.append(d1)
            #                                 request_type_repeate.append(self.records[f'{user_id}']['servicetag1'][d1]['requestType'])

            #                         duplicate_url.append(d1)

            #                         #print(set(self.records[f'{user_id}']['servicetag1'][d1]['exercisable_parameters']))

            #                     # if (self.records[f'{user_id}']['servicetag1'][d1]['header'].keys())== (self.records[f'{user_id}']['servicetag1'][d2]['header'].keys()):
            #                     #     duplicate_header = True

            #                 # if (duplicate_exercisable_parameters == True):
            #                 #     duplicate_url.append(d1)

            # duplicate_urls = set(duplicate_url)
            # # for i in duplicate_urls:
            # #     if i in keep_urls:
            # #         duplicate_urls.pop(i)
            # for url in duplicate_urls :
            #     if url not in keep_urls:
            #         #print(url)
            #         del self.records[f'{user_id}']['servicetag1'][url]
            #     # if (duplicate_url.index(url)) % 2 == 0:

            # # for k,v in
            # ##########
            if check_urls==0:
                #'was_db'=was.environment["current_db"]
                db=self.mongo.create_database(db_channel,'was_db')

                coll=self.mongo.create_collection(db,'url_store')
                # app_status = self.mongo.insert_document(coll, )

                app_status=self.finalUrlStoreTempTable.update({"application_id":self.applicationId},
                    {"$set":{"urls":records}})
                manual_crawl=self.mongo.create_collection(db,'pre_crawl_store')
                manual_doc=self.mongo.delete_document(manual_crawl,{'application_id':self.applicationId})

                if app_status=='update_success':
                    self.log.info("URL Store Genarated")

                    message=f"Crawl URL Store updated for application {self.applicationName} ({self.applicationId})"
                    util.Notification().send_notification(message=message,
                        application_id=self.applicationId,
                        operation='Crawl',
                        application_name=self.applicationName)



            else:
                final_data={}
                old_urls_data={}
                update_data={}
                for i in cur:
                        if 'urls' in i:
                            for k,v in i['urls'].items():
                                if k!=user_id:
                                    final_data[k]=v
                                else:
                                    old_urls_data[k]=v
                                    self.log.info(" Updating existing URL store")

                            # update URL_Store code
                            url_data=0
                            for service_tag in self.service_ip_map.keys():
                                if len(old_urls_data)>=1:
                                    for i in old_urls_data[user_id][service_tag].values():
                                            url_id="url_"+str(url_data)
                                            update_data[url_id]=i
                                            url_data+=1

                                    for i in records[user_id][service_tag].values():
                                        url_id="url_"+str(url_data)
                                        update_data[url_id]=i
                                        url_data+=1

                                    final_data[user_id]={}
                                    final_data[user_id][service_tag] = self.remove_duplicates(update_data)
                                else:
                                    final_data[user_id]={}
                                    final_data[user_id][service_tag] = records[user_id][service_tag]

                #'was_db'=was.environment["current_db"]
                db=self.mongo.create_database(db_channel,'was_db')

                coll=self.mongo.create_collection(db,'url_store')
                # app_status = self.mongo.insert_document(coll, )

                app_status=self.finalUrlStoreTempTable.update({"application_id":self.applicationId},
                    {"$set":{"urls":final_data}})
                manual_crawl=self.mongo.create_collection(db,'pre_crawl_store')
                manual_doc=self.mongo.delete_document(manual_crawl,{'application_id':self.applicationId})

                if app_status=='update_success':
                    self.log.info("URL Store Genarated")

                    message=f"Crawl URL Store updated for application {self.applicationName} ({self.applicationId})"
                    util.Notification().send_notification(message=message,
                        application_id=self.applicationId,
                        operation='Crawl',
                        application_name=self.applicationName)





        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            print("zap details updated")
            self.log.error(e)
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}) at time of URL store generation."
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})
        finally:
            self.urlStoreTempTable.delete_many({"crawl_id":self.crawl_id})

    def authExerciser(self):
        try:
            # Auth exerciser

            from config import was
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            coll=self.mongo.create_collection(db,'url_store')
            application_authentication=self.mongo.find_document(coll,{'application_id':self.applicationId},
                {'authentication':True})
            coll=self.mongo.create_collection(db,'vault')
            app_creds=self.mongo.find_document(coll,{'application_id':self.applicationId},
                {'authentication':True})
            # decrypted_passwd = util.Authentication().decrypt_password(
            #     app_creds['authentication']['framework_authentication']['key'],
            #     app_creds['authentication']['framework_authentication']['password'])

            # session.proxies = {'http': f'http://127.0.0.1:8080'}
            self.log.info("Application Auth is in progress")

            fw_auth='not_applicable'
            if application_authentication['authentication']['framework_authentication']['login']==True:
                self.log.info(f"Verifying framework-authentication for application- {self.applicationId}")

                if application_authentication['authentication']['framework_authentication']['type'].upper()=='NTLM':
                    session.auth=HttpNtlmAuth(
                        f"{application_authentication['authentication']['framework_authentication']['domain']}\\{application_authentication['authentication']['framework_authentication']['username']}",
                        decrypted_passwd,session)
                    response=session.get('http://10.20.12.35:80/')
                    if response.status_code==200:
                        print('NTLM authentication successful')
                        fw_auth='success'
                    elif response.status_code!=200:
                        print(f'NTLM authentication not successful- {response.text}')
                        fw_auth='failure'

            self.log.info(f"Validating application authentication for application- {self.applicationId}")
            app_auth='not_applicable'
            # self.user_id =[]
            if application_authentication['authentication']['application_authentication'][
                'login']==True and 'user_0' not in self.usersInfo.keys():
                if len(self.usersInfo)==1:
                    user_detail=dict()
                    for k,v in self.usersInfo.items():
                        for k1,v1 in application_authentication['authentication']['application_authentication'][
                            'users'].items():
                            if k==k1:
                                # self.user_id.append(k1)
                                user_detail.update(v1)
                else:
                    return 1

                if 'http_stream' in user_detail:
                    for pkt in user_detail['http_stream']:
                        if pkt["method"]=="POST" and "requestBody" in pkt:
                            session=requests.Session()
                            response=session.post(url=pkt['url'],data=pkt['requestBody'])
                            if response.status_code==200:
                                app_auth='success'
                                active_session=session
                                self.isInteractiveAuth=True
                            else:
                                if "active_session" in locals():
                                    active_session.close()

                    if app_auth=='success':
                        self.log.info(
                            "Application authentation using HTTP stream from interactive authentication is successful")
                        # self.crawlStart()
                    else:
                        self.log.info(
                            "Application authentation using HTTP stream from interactive authentication is not successful")

                else:
                    coll=self.mongo.create_collection(db,'applications')
                    end_time=time.time()
                    cache_map=dict()
                    cache_map['application_id']=self.applicationId
                    cache_map['crawl_state']='aborted'
                    cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
                    app_status=self.mongo.update_document(coll,{
                        '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                            'crawl.crawl_aborted':end_time}},
                        {'application_id':self.applicationId},upsert=True)
                    self.log.error("Crawl aborted, HTTP_Stream not present")

                    message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}) as HTTP stream was not found"
                    util.Notification().send_notification(message=message,
                        application_id=self.applicationId,
                        operation='Crawl',
                        application_name=self.applicationName)
                    return "HTTP_stream_not_present"

            # print("Application having anonymus user")

            # self.user_id=[self.usersInfo['user_id']]
            self.crawlStart()

        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.log.error(e)
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId}). Interactive authentication unsucessful"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})
        finally:
            self.killZap(self.zap)

    def crawlStart(self):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.log.info("starting crawl process")
            self.fetchAvailableZapPort()
            self.log.info("application URl",self.applicationURL)
            self.log.info("zap port found",self.ZapPort)
            self.log.info("zap IP",self.ZapIP)
            self.log.info("Starting Crawl with ApplicationURL {0}, ZapPort {1}, ZapIP {2}".format(self.applicationURL,
                self.ZapPort,
                self.ZapIP))
            self.startZAP()
            time.sleep(55)
            self.log.info('Spidering target {}'.format(self.target))
            self.crawlApplication()

            self.processUrlStore()
            self.log.info("Crawl Completed successfully")


        except Exception as e:
            coll=self.mongo.create_collection(db,'applications')
            end_time=time.time()
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            app_status=self.mongo.update_document(coll,{
                '$set':{'detail.state':'aborted','crawl.crawl_state':'aborted',
                    'crawl.crawl_aborted':end_time}},
                {'application_id':self.applicationId},upsert=True)
            self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                "$set":{"portStatus":"active","applicationURL":" ","userInfo":"",
                    "applicationId":" ","updated_dt":datetime.now().isoformat(),
                    "applicationName":" ","applicationAPIKey":" ","sacnId":""}})
            print("zap details updated")
            self.log.error(e)
            message=f"Crawl aborted for application {self.applicationName} ({self.applicationId})."
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})
        finally:
            self.killZap(self.zap)

    def crawlProcess(self):
        try:
            if self.authExerciser() not in ['HTTP_stream_not_present']:
                from config import was
                self.redis=util.Database().Redis()
                self.mongo=util.Database().Mongo()
                db_channel=self.mongo.connect(host=was.was['database'])
                #'was_db'=was.environment["current_db"]
                db=self.mongo.create_database(db_channel,'was_db')
                cache_channel=self.redis.connect(host=was.was['cache'])
                coll=self.mongo.create_collection(db,'applications')
                application=self.mongo.find_document(coll,{'application_id':self.applicationId})
                cache_map=dict()
                cache_map['application_id']=self.applicationId

                time.sleep(10)
                crawl_state='completed'
                end_time=time.time()
                self.log.info(f"Transitioning crawl state to {crawl_state}")
                cache_map['crawl_state']=crawl_state
                cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
                #'was_db'=was.environment["current_db"]
                self.dbConn=self.mongoClient['was_db']
                self.ZAPPortsTable=self.dbConn['zap_ports']
                self.ZAPPortsTable.update_one({'zapPort':self.ZapPort},{
                    "$set":{"portStatus":"active","applicationURL":"","userInfo":"",
                        "applicationId":"","updated_dt":datetime.now().isoformat(),
                        "applicationName":"","applicationAPIKey":"","scanId":""}})
                print("zap details updated")
                
                exist_application=self.mongo.find_document(coll,{'application_id':self.applicationId})
                
                db_users = []
                for i in exist_application['crawl']['users']:
                    db_users.append(i['user_id'])
                
                updated_users_list = exist_application['crawl']['users']
                
                # if 'users' in self.usersInfo['crawl']:
                for k,v in self.usersInfo.items():
                    #current_uers_id = v['user_id']
                    if len(exist_application['crawl']['users'])!= 0:
                        if v['user_id'] not in db_users:
                            updated_users_list.append(v)
                    else:
                        updated_users_list.append(v)

                app_status=self.mongo.update_document(coll,{
                    '$set':{'detail.state':'attack_ready','detail.url_store':'genarate',
                        'crawl.crawl_state':crawl_state,
                        'crawl.crawl_completed':end_time,
                        'crawl.users':updated_users_list}},
                    {'application_id':self.applicationId},upsert=True)

                application=self.mongo.find_document(coll,{'application_id':self.applicationId})
                if app_status=='update_success':
                    try:
                        subject=f"Crawl operation completed"
                        message=f"Crawl operation completed for application {application['detail']['name']} ({self.applicationId})"
                        util.Notification().send_notification(message=message,
                            application_id=self.applicationId,
                            operation='Crawl',
                            application_name=application['detail']['name'],
                            subject=subject)
                        # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                        #                                   message=message, application_id=self.applicationId,
                        #                                   application_name=application['detail']['name'])
                        # util.Notification().smtp(subject=subject, message=message)
                        self.log.info(message)
                    except Exception as e:
                        return jsonify({'data':{'code':2030,'status':'error',
                            'message':'Unable to send msg : SMPT ERROR','exception':e}})
                time.sleep(10)
                cache_channel.hdel('crawl',self.applicationId)


        except Exception as e:
            self.log.error(e)
            return jsonify({'data':{'code':2030,'status':'error',
                'message':'Unable to Process Crawl : CrawlProcess.','exception':e}})


        finally:
            if "cache_channel" in locals() and cache_channel:
                del cache_channel
            if "db_channel" in locals() and db_channel:
                db_channel.close()

    def crawl_for_interactive_auth(self):
        try:
            bAuthFailed=False
            bAuthCrawlFail=False
            application_authentication=self.mongo.find_document(self.finalUrlStoreTempTable,
                {'application_id':self.applicationId},
                {'authentication':True})
            if 'authentication' in application_authentication and 'application_authentication' in\
                    application_authentication['authentication'] and 'login' in\
                    application_authentication['authentication']['application_authentication']:
                if application_authentication['authentication']['application_authentication']['login']==True:
                    if 'users' in application_authentication['authentication']['application_authentication']:
                        for _,v1 in self.usersInfo.items():
                            if 'http_stream' in v1 and 'type' in v1:
                                if v1['type'].lower()=="interactive":
                                    login_url=""
                                    logout_url=""
                                    username=""
                                    homepage_url=""
                                    context_name=self.context_name
                                    include_url=[]
                                    if 'login_url' in application_authentication['authentication'][
                                        'application_authentication']:
                                        login_url=\
                                            application_authentication['authentication']['application_authentication'][
                                                'login_url']
                                        if 'logout_url' in application_authentication['authentication'][
                                            'application_authentication']:
                                            logout_url=\
                                                application_authentication['authentication'][
                                                    'application_authentication'][
                                                    'logout_url']
                                        if 'username' in v1:
                                            username=v1['username']
                                        if 'homepage_url' in application_authentication['authentication']:
                                            homepage_url=application_authentication['authentication']['homepage_url']
                                        else:
                                            self.log.warning(f"Homepage URL not found, defaulting to login URL")
                                            homepage_url=logout_url
                                        if homepage_url:
                                            include_url.append(
                                                f"{urlparse.urlparse(homepage_url).scheme}://{urlparse.urlparse(homepage_url).netloc}/.*")
                                            include_url.append(homepage_url)
                                            if homepage_url!=login_url:
                                                include_url.append(login_url)
                                        context_id=self.create_new_context()
                                        if (str(context_id).isnumeric()):
                                            self.add_service_to_context(url_list=include_url)
                                            set_data=[]
                                            for i in v1['http_stream']:
                                                if "method" in i:
                                                    if i["method"].lower()=="post" and "requestBody" in i:
                                                        if "formData" in i["requestBody"]:
                                                            form_data=""
                                                            for k,v in i["requestBody"]["formData"].items():
                                                                val="".join(v)
                                                                form_data=f"{form_data}&{k}={val}".strip("&")
                                                            set_data.append(form_data)
                                            set_data=set(set_data)
                                            if len(set_data)>0:
                                                app_username=""
                                                app_password=""
                                                bHasUsername=True
                                                bHasPassword=True
                                                login_request_data=max(list(set(set_data)),key=len)
                                                for i in list(set_data):
                                                    for fd in i.split("&"):
                                                        j=fd.split("=")
                                                        if "username" in j[0].lower() or "user_name" in j[
                                                            0].lower() or "login" in j[0].lower():
                                                            if bHasUsername:
                                                                app_username=j[1]
                                                                bHasUsername=False
                                                        if "password" in j[0].lower():
                                                            if bHasPassword:
                                                                app_password=j[1]
                                                                bHasPassword=False
                                                if bHasUsername:
                                                    self.log.warning(
                                                        "Unable to fetch Username http_stream data, Using only formData for auth crawl")
                                                if bHasPassword:
                                                    self.log.warning(
                                                        "Unable to fetch Password from http_stream data, Using only formData for auth crawl")
                                                form_based_config='loginUrl='+urllib.parse.quote(
                                                    login_url)+'&loginRequestData='+urllib.parse.quote(
                                                    login_request_data)
                                                auth=self.zap.authentication.set_authentication_method(context_id,
                                                    'formBasedAuthentication',
                                                    form_based_config)
                                                logout_regex=urlparse.urlparse(logout_url).path
                                                logout_regex=logout_regex.split("/")[-1]
                                                logged_in_regex=f'\Q{logout_regex}\E'
                                                self.zap.authentication.set_logged_in_indicator(context_id,
                                                    logged_in_regex)
                                                if auth.lower()=="ok":
                                                    user_id=self.zap.users.new_user(context_id,username)
                                                    user_auth_config='username='+urllib.parse.quote(
                                                        app_username)+'&password='+urllib.parse.quote(app_password)
                                                    self.zap.users.set_authentication_credentials(context_id,user_id,
                                                        user_auth_config)
                                                    if (str(user_id).isnumeric()):
                                                        self.zap.users.set_user_enabled(context_id,user_id,'true')
                                                        self.zap.forcedUser.set_forced_user(context_id,user_id)
                                                        self.zap.forcedUser.set_forced_user_mode_enabled('true')
                                                        scanid=self.zap.spider.scan_as_user(context_id,user_id,
                                                            homepage_url,
                                                            recurse='true',
                                                            apikey=self.ZapAPIKey)
                                                        if (str(scanid).isnumeric()):
                                                            return scanid
                                                        self.log.error(
                                                            f"Failed to start scan. Expected OK found {scanid}")
                                                        bAuthCrawlFail=True
                                                else:
                                                    self.log.error(
                                                        f"Failed to create formBasedAuthentication. Expected OK found {auth}")
                                                    bAuthCrawlFail=True
                                            else:
                                                self.log.error(f"Failed to fetch any method[POST]->requestBody->formData from http_stream! Possibly http_stream maynot \
                                                                have required data")
                                                bAuthCrawlFail=True
                                        else:
                                            self.log.error(f"Failed to create context. Context returned {context_id}!")
                                            bAuthCrawlFail=True
                                    else:
                                        self.log.error(f"Authenticated Crawl failed; Expected 'login_url';")
                                        bAuthFailed=True
                                else:
                                    self.log.error(
                                        f"Authenticated Crawl failed; Expected 'interavctive'; found {v1['type']}")
                                    bAuthFailed=True
                            else:
                                self.log.error(
                                    f"Authenticated Crawl failed; Expected 'http_Stream' for users in urls collections")
                                bAuthFailed=True
                    else:
                        self.log.error(f"Authenticated Crawl failed; Expected 'users' in 'authentication'->'application_authentication' in urls collections \
                                        found :{application_authentication['authentication']['application_authentication']}")
                        bAuthFailed=True
                else:
                    self.log.error(f"Authenticated Crawl failed; 'authentication'->'application_authentication'->'login' expected True, \
                                        found {application_authentication['authentication']['application_authentication']['login']}")
                    bAuthFailed=True
            else:
                self.log.error(
                    "Authenticated Crawl failed; 'authentication'/'application_authentication'/'login' not found in application configuration collection")
                bAuthFailed=True

            if (bAuthFailed):
                self.log.error(
                    "AUTHENTICATED CRAWL FAILED; Application not configured for authenticated Crawl, defaulting to regular Crawl!")
            if (bAuthCrawlFail):
                self.log.error(
                    f"AUTHENTICATED CRAWL FAILED; Unable to perform Auth Crawl, defaulting to regular Crawl!")
            return None
        except Exception as e:
            self.log.error(f"AUTHENTICATED CRAWL FAILED; Exception raised: {e}")
            return None

    def killZap(self,zap):
        # portNumRaw = self.fetchZAPProcessId(self.ZapAPIKey)
        # if  len(portNumRaw) >= 1:
        #     self.zapTrigger = ("kill {0}").format(portNumRaw)
        #     subprocess.Popen([self.zapTrigger], shell=True)
        zap.core.shutdown()

    def remove_duplicates(self,source_dict,perform_union=True):
        url_list=[]
        url_to_urlid={}
        for ind1,d1 in source_dict.items():
            append_str=""
            append_str+=d1['attack_url']
            append_str=append_str+"#"+d1['requestType']
            url_to_urlid.setdefault(append_str,[]).append(ind1)
            exercisable_parameters=""
            for ep in set(d1['exercisable_parameters']):
                exercisable_parameters=exercisable_parameters+"|"+ep
            append_str=append_str+"#"+exercisable_parameters.strip("|")
            header=""
            for hdr in set(d1['header']):
                header=header+"|"+hdr
            append_str=append_str+"#"+header.strip("|")
            url_list.append(append_str)

        just_urls=set(url_list)
        url_store=[]
        for d1 in just_urls:
            d1_attack_url=d1.split("#")[0]
            d1_method=d1.split("#")[1]
            d1_excercisable_parameter=set(d1.split("#")[2].split("|"))
            d1_header=set(d1.split("#")[3].split("|"))

            url_store_excercisable_parameter=deepcopy(d1_excercisable_parameter)
            url_store_header=deepcopy(d1_header)
            for d2 in just_urls:
                if d1!=d2:
                    d2_attack_url=d2.split("#")[0]
                    d2_method=d2.split("#")[1]
                    if all([(d1_attack_url==d2_attack_url),(d1_method==d2_method)]):
                        d2_ep=set(d2.split("#")[2].split("|"))
                        d2_h=set(d2.split("#")[3].split("|"))
                        if perform_union:
                            url_store_excercisable_parameter=deepcopy(
                                url_store_excercisable_parameter.union(d1_excercisable_parameter.union(d2_ep)))
                            url_store_header=deepcopy(url_store_header.union(d1_header.union(d2_h)))

            e_params_list=list(sorted(url_store_excercisable_parameter))
            header_params_list=list(sorted(url_store_header))
            id="#".join(d1.split("#")[0:2]).strip("#")
            data={
                "attack_url":d1_attack_url,
                "requestType":d1_method.upper(),
                "exercisable_parameters":[i for i in e_params_list if i!=""],
                "parameters":self.get_parameters_value(id=id,url_to_urlid=url_to_urlid,
                    excercisable_parameters=e_params_list,source_dict=source_dict),
                "header":self.get_header_value(id=id,url_to_urlid=url_to_urlid,
                    excercisable_parameters=header_params_list,source_dict=source_dict)
            }
            if data not in url_store:
                url_store.append(data)

        final_url_store={}
        for ind,data in enumerate(url_store):
            url_id=f"url_{ind}"
            data['url_id']=url_id
            data['user_agent']=data['header']['User-Agent']
            data['crawl_id']=self.crawl_id
            final_url_store[url_id]=data
        return final_url_store

    def get_parameters_value(self,id,url_to_urlid,excercisable_parameters,source_dict):
        return_dict={}
        for data in excercisable_parameters:
            if data!="":
                for ind,_ in enumerate(url_to_urlid[id]):
                    params=source_dict[url_to_urlid[id][ind]]["parameters"]
                    if data in params.keys():
                        return_dict[data]=source_dict[url_to_urlid[id][ind]]["parameters"][data]
                        break
        return return_dict

    def get_header_value(self,id,url_to_urlid,excercisable_parameters,source_dict):
        return_dict={}
        for data in excercisable_parameters:
            if data!="":
                for ind,_ in enumerate(url_to_urlid[id]):
                    params=source_dict[url_to_urlid[id][ind]]["header"]
                    if data in params.keys():
                        return_dict[data]=source_dict[url_to_urlid[id][ind]]["header"][data]
                        break
        return return_dict

    def service_name_generator(self,default_name=None):
        if default_name is not None:
            return default_name
        # TODO: add logic for service name generator
        return str(uuid.uuid4().hex)

    def get_service_urls(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                cms['ipv4_address'])
            services=fw.CMS(cms['ipv4_address']).application_services(application_id=self.applicationId,
                header=cms_services_header)
            for service in services:
                service_ip=None
                service_name=service.get("serviceTag","")
                service_ip=service.get("applicationInstances",[""])
                if service_ip is not None and isinstance(service_ip,list):
                    if service_name=="":
                        service_name=service_ip[0].replace(".","_") if service_ip[0]!="" else "default_tag"
                    self.service_ip_map[service_name]=service.get("applicationInstances",[""])[0]
            return True
        except Exception as e:
            self.log.error(f"Exception: raised when trying to get application services {e}")
            return False

    def add_urls_into_context(self,include_url):
        try:
            if len(include_url)==0 and not isinstance(include_url,list):
                self.log.error(f"include_urls should be type list; found {type(include_url)}")
                return False

            for urls in include_url:
                context_return=self.zap.context.include_in_context(str(self.context_name),
                    urls).lower()
                if context_return.lower()!='ok':
                    self.log.error(
                        f"Failed to add {urls} to context! returned {context_return}, attempting to perform crawl")
                    #return False
            return True
        except Exception as e:
            self.log.error(f"Exception: {e} when trying to perform context inclusion")
            return False

    def add_service_to_context(self,url_list=[]):
        include_url=[]
        include_url.extend(url_list)
        self.get_service_urls()
        if len(self.service_ip_map)>0:
            for services_ip in self.service_ip_map.values():
                if services_ip != "":
                    include_url.append(f"https?://w*?.?{services_ip}.*")
        self.add_urls_into_context(include_url=include_url)

    def create_new_context(self):
        context_list=self.zap.context.context_list
        if len(context_list)>0:
            self.context_name=context_list[0]
            return self.zap.context.context(context_list[0])["id"]
        return self.zap.context.new_context(self.context_name)

    def get_service_name_for_hostname(self,hostname=None):
        if len(self.service_map)==0:
            self.get_service_urls()
        if hostname is not None:
            for key,value in self.service_map.items():
                if value in hostname:
                    return key
        return "servicetag1"

    def crawl_for_non_interactive_auth(self):
        try:
            context_id=self.create_new_context()
            if (str(context_id).isnumeric()):
                self.add_service_to_context()
            return True
        except Exception as e:
            self.log.error(f"Exception: Failed to set context for regular scan. {e}")
            return False
        finally:
            self.scanID=self.zap.spider.scan(self.target,apikey=self.ZapAPIKey)

    def perform_zap_scan_for_manual_urls(self,crawl_list=[]):
        for urls in crawl_list:
            self.scan_ids.append(self.zap.spider.scan(urls["attack_url"],apikey=self.ZapAPIKey))

    @property
    def scanID(self):
        return self.__scanId

    @scanID.setter
    def scanID(self,value):
        self.__scanId=value
        self.scan_ids.append(value)
    
    def get_service_tag_name(self,url=None):
        service_tag=was.configuration['crawl']['default_service_tag']
        try:
            if url is not None:
                ip=urlparse.urlparse(url).netloc.split(":")[0]
                try:
                    service_tag=list(self.service_ip_map.keys())[list(self.service_ip_map.values()).index(ip)]
                except ValueError:
                    self.log.error(f"Crawl; Index not found for {ip} in list {self.service_ip_map}; Defaulting to {service_tag}")
                except Exception as e:
                    self.log.error(f"Crawl; Exception raised {e}")
        except Exception as e:
            self.log.error(f"Crawl; Exception raised {e}")
        return service_tag


class Manual:
    def __init__(self,applicationId):
        self.applicationId=applicationId
        self.log=util.Crawl_Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()

    def createFinalJson(self):
        try:
            import json
            # self.logFileDir = '/home/virsec'
            # self.logFile = 'tempURLData3241.json'
            # self.crawlType = crawlType
            self.JSONExtract=''
            if os.path.exists(was.configuration['manual_crawl']['upload_json_name']):
                with open(was.configuration['manual_crawl']['upload_json_name'],"r") as f:
                    data=f.read()

                    with open(was.configuration['manual_crawl']['final_url'],"w") as lgfile:
                        lgfile.write("[")
                        datanew=data[1:]
                        lgfile.write(datanew)
                        lgfile.write("]")
                    return True


        except Exception as e:
            self.log.error('Unable to Process UploaderJob : logToJSON.')
            self.log.error('Exception',e)
            return False
            # sys.exit(2025)
        finally:
            if os.path.exists(was.configuration['manual_crawl']['upload_json_name']):
                os.remove(was.configuration['manual_crawl']['upload_json_name'])

    def precrawlUrlStore(self):
        try:
            self.mongoClient=MongoClient(host=was.was["database"])
            #'was_db'=was.environment["current_db"]
            self.dbConn=self.mongoClient['was_db']
            self.preCrawlTable=self.dbConn['pre_crawl_store']
            self.finalUrlStoreTempTable=self.dbConn['url_store']
            preCrawl=self.preCrawlTable.find({'application_id':self.applicationId}).limit(1)
            # print(list(preCrawl))
            preCrawl_dict={}
            for i in preCrawl:
                preCrawl_dict=i['manual']['urls']

            preUrlList=[]
            for _,v in preCrawl_dict.items():
                preUrlList.append(v)

            cursor=self.finalUrlStoreTempTable.find({'application_id':self.applicationId}).limit(1)
            urlStore={}
            for i in cursor:
                urlStore=i['urls']['urls']

            urlStore_list=[]
            for _,v in urlStore.items():
                urlStore_list.append(v['attack_url'])

            j=len(urlStore_list)
            urls=[]
            for i in preUrlList:
                if i['attack_url'] not in urlStore_list:
                    url='url_'+str(j+1)
                    i.pop('hostname')
                    i.pop('time_stamp')
                    # url=i
                    urls.append({f'{url}':i})
                    j+=1

            if len(urls)>=1:
                for i in cursor:
                    self.finalUrlStoreTempTable.update_many({"_id":i["_id"]},{"urls":{"$exists":True}},
                        {"$set":{"urls":urls}})
        except Exception as e:
            self.redis=util.Database().Redis()
            cache_channel=self.redis.connect(host=was.was['cache'])
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            message=f"Crawl aborted for application {self.applicationId}"
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            return jsonify({'data':{'code':2026,'status':'error',
                'message':'Unable to Url store :','exception':e}})

    def precrawl(self):
        try:
            self.log.info("Precrawl started")

            self.mongoClient=MongoClient(host=was.was["database"])
            #'was_db'=was.environment["current_db"]
            self.dbConn=self.mongoClient['was_db']
            self.preCrawlTable=self.dbConn['pre_crawl_store']
            self.finalUrlStoreTempTable=self.dbConn['url_store']
            jsonList=[]
            jsonFinal=['hostname','attack_url','user_agent','requestType','exercisable_parameters',
                'parameters','header']

            cursor=self.finalUrlStoreTempTable.find({"application_id":self.applicationId})

            for host in cursor:
                h=host['authentication']['homepage_url']
                parsed_url=urllib.parse.urlparse(h)
                hostname=parsed_url.netloc
                # print(host)
                break

            if self.createFinalJson():
                db_channel=self.mongo.connect(host=was.was['database'])
                #'was_db'=was.environment["current_db"]
                db=self.mongo.create_database(db_channel,'was_db')
                with open(was.configuration['manual_crawl']['final_url'],"r") as finallog:
                    json_data=json.load(finallog)
                    # print(json_data)
                    for i in json_data:
                        # if "Host" in i.keys():
                        #     if hostname == i['Host']:
                        jsonList.append(i)
                    del_key=[]

                    for i in jsonList:
                        if "Host" in i.keys() and "requestURI" in i.keys() and "User-Agent" in i.keys():
                            i['hostname']=i.pop('Host')
                            i['attack_url']=i.pop('requestURI')
                            i['user_agent']=i.pop('User-Agent')
                            # i['requestType'] = i.pop('requestType')
                            # i.pop('time_stamp')
                            for k,v in i.items():
                                if k not in jsonFinal:
                                    del_key.append(k)

                    finalList=[]
                    for i in jsonList:
                        if "attack_url" in i.keys():
                            res=dict([(key,val) for key,val in i.items() if key not in del_key])

                            finalList.append(res)

                    document={}
                    document['application_id']=self.applicationId
                    document['manual']={}
                    document['manual']['urls']={}
                    j=0
                    urls=[]
                    for data in finalList:
                        cursor=self.preCrawlTable.find({"attack_url":data['attack_url']})
                        cunt=cursor.count()
                        if cunt==0:
                            uri='url_'+str(j)

                            document['manual']['urls'][uri]=data
                            document['manual']['urls'][uri].update({'url_id':uri})
                            j+=1
                    # self.preCrawlTable.insert(document)

                    if len(document['manual']['urls'])>=1:
                        coll=self.mongo.create_collection(db,'pre_crawl_store')
                        self.mongo.update_document(coll,{'$set':{'manual.urls':document['manual']['urls']}},
                            {'application_id':self.applicationId},upsert=True)
                        # cursor = self.preCrawlTable.find({"application_id": self.applicationId})
                        # for i in cursor:
                        #     self.preCrawlTable.update_one({"_id": i['_id']},
                        #                                 {'$set': {'manual.urls': document['manual']['urls']}},
                        #                                 {'application_id': self.applicationId}, upsert=True)
                    # self.precrawlUrlStore()
                    self.log.info("url store genarated")


        except Exception as e:
            self.redis=util.Database().Redis()
            cache_channel=self.redis.connect(host=was.was['cache'])
            cache_map=dict()
            cache_map['application_id']=self.applicationId
            cache_map['crawl_state']='aborted'
            cache_channel.hmset('crawl',{self.applicationId:str(cache_map)})
            message=f"Crawl aborted for application {self.applicationId} "
            util.Notification().send_notification(message=message,
                application_id=self.applicationId,
                operation='Crawl',
                application_name=self.applicationName)
            # return jsonify({'data': {'code': 2026, 'status': 'error',
            #                          'message': 'Unable to genarate Precrawl Url store :', 'exception': e}})
        finally:
            if os.path.exists(was.configuration['manual_crawl']['final_url']):
                with open(was.configuration['manual_crawl']['final_url'],"r+") as f:
                    f.truncate(0)

    def get_manual_crawls(self):
        try:
            manual_URLS=[]
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'pre_crawl_store')
            manual_doc=self.mongo.find_document(coll,{'application_id':self.applicationId})
            if 'manual' in manual_doc:
                manual=manual_doc.get('manual',{}).get('urls',{})
                for _,v in manual.items():
                    manual_URLS.append(v)
            return manual_URLS
        finally:
            if db_channel:
                db_channel.close()