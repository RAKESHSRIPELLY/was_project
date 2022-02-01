__author__ = 'JG'

from redis.connection import SYM_DOLLAR
from lib import utility as util, framework as fw
from config import was, environment as env
import time
import requests
from urllib.parse import quote
import os
import traceback
import json
from json import loads, dumps
# from requests.utils import quote
from multiprocessing import Process, Pipe
from multiprocessing.pool import ThreadPool
from jumpssh import SSHSession
from cvss import CVSS2, CVSS3

class Attack:

    def __init__(self, application_id):
        self.application_id = application_id

        self.log = util.Log()
        self.redis = util.Database().Redis()
        self.mongo = util.Database().Mongo()

        self.count = 0

    def initiate(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')


            #tables in mongodb
            self.app_store = self.mongo.create_collection(db, 'applications')
            self.url_store = self.mongo.create_collection(db, 'url_store')
            self.payload_store = self.mongo.create_collection(db, 'payload_store')            
            app_data = self.mongo.find_document(self.app_store, {'application_id': self.application_id})

            self.auth_details = self.mongo.find_document(self.url_store, {'application_id': self.application_id},{'authentication': True})
            self.app_auth_details= self.auth_details['authentication']['application_authentication'] 
            self.fw_auth_details= self.auth_details['authentication']['framework_authentication'] 
            self.log.info(f"Validating if application instance(s) is in appropriate state")

            cache_map = {'application_id': self.application_id,  'attack_state':  'in_progress'}
            cache_channel.hmset('attack', {self.application_id: str(cache_map)})
            cache_channel.hset(self.application_id, 'attack_state', 'in_progress')

            # cache_map = dict()
            # cache_map['application_id'] = self.application_id
            # cache_map['attack_state'] = app_data['attack']['attack_state']
            # cache_channel.hmset('attack', {self.application_id: str(cache_map)})

            # cache_temp = util.ConvertData((cache_channel.hmget('attack', self.application_id)[0]).decode('utf-8')).framework_compatible()
            
            #Check if attack is a Fresh start or Resume
            if "attack_pause_request_count" in app_data['attack']:
                #We are Resuming an attack
                self.attack_pause_request_count= app_data['attack']['attack_pause_request_count']
                self.log.info(f"Resuming the Attack From Request Number :  {self.attack_pause_request_count}")
            else:
                #We are initiating Fresh attack.
                self.attack_pause_request_count= 0
                self.log.info(f"Initiating the Attack From Request Number :  {self.attack_pause_request_count}")



#  Get all instances of an Application ID
            application_services = self.mongo.find_document(self.url_store, {'application_id': self.application_id},  {'services': True})
            if 'services' in application_services:
                application_instances = set()
                for k, v in application_services['services'].items():
                    for instance in v['instances']:
                        application_instances.add(instance)
                self.log.info(f"App instances are : {application_instances}")


#   Get all CMS Instances, 
                cms = util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                access_token = fw.CMS(cms['ipv4_address']).token_status()
                cms_services_header = util.Authentication().create_http_header('services', access_token, cms['ipv4_address'])
                cms_application_instances = fw.CMS(cms['ipv4_address']).application_instances(self.application_id,cms_services_header)
                self.log.info(f"CMS App instances are : {cms_application_instances}")
                # if cache_channel.exists('cms'):
                #     cms = util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                # else:
                #     self.log.critical(f"CMS is not configured to fetch applications")
                #     return 'cms_not_configured'

                # self.log.info(f"Querying CMS for application {self.application_id}")
                # app_status, app_name,app_ip_address = fw.CMS(cms['ipv4_address']).application_status_v1(self.application_id,
                #                                                                     cms_services_header,access_token)


                # cms_application_instances= [{'state': app_status, 'name': app_name, 'ipAddress': app_ip_address    }]

#  Check if atleast one instance is available with NORMAL STATE in CMS. 
                attack_ready = False  
                for instance in application_instances:
                    for app_instance in cms_application_instances:

                        # application_status, application_name = fw.CMS(cms['ipv4_address']).application_status_v1(self.application_id,cms_services_header,access_token)

                        if instance == app_instance['serverNetworkInfo']['ipAddress'] :# and app_instance['status'] in ['NORMAL', 'THREAT', 'ATTACK']: #'PROVISIONED':  #chg
                        # if instance == app_instance['ipAddress'] and app_instance['state'] in ['NORMAL', 'THREAT', 'ATTACK']: #'PROVISIONED':  #chg
                            attack_ready = True
                            # self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['state']} state")
                            break  
                        else:
                            attack_ready = False
                            # self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['state']} state")

                    if attack_ready== True:
                        break

                if attack_ready == True:
                    self.log.info(f"Validating application authentication for application- {self.application_id}")

                    self.attack_users = self.mongo.find_document(self.app_store, {'application_id': self.application_id},{'attack.users': True})
                    
                    
                    if self.app_auth_details['login'] == True :
                        app_validation_status= self.app_Validation()
                    else:
                        app_validation_status= "success"

                    if app_validation_status!= "success":
                        self.log.info(f"Application Authentication validation Failed")
                        return 'AppAuth_validation_Failed'


                    #Loop through Users and create sesssions
                # if self.app_auth_details['login'] == True :
                    for self.attack_user,attack_user_data in self.attack_users['attack']['users'].items():  #Looping all users.
                        app_session_status= "Failure"

                        if self.app_auth_details['login'] ==  True:
                            self.users_login_calls= self.app_auth_details["users"]
                            if self.attack_user in self.users_login_calls:
                                self.log.info(f"User {self.attack_user} exists in both Attack List and Login List")

    #   Looping through all Login calls http_streams
                                for login_call in self.users_login_calls[self.attack_user]["http_stream"]:     
                                    if login_call["method"]== "POST" and "requestBody" in login_call:
                                        self.log.info(f"Application call has been made for user: {self.attack_user} for requestID:  {login_call['requestId']} ")

                                        #Create a new session
                                        app_session = requests.Session()
                                        response = app_session.post(url=login_call['url'], data=login_call['requestBody'])
                                        if response.status_code == 200:
                                            self.app_active_session= app_session
                                            app_session_status= "success"

                                        else:
                                            app_session.close()
                            else:
                                self.log.info(f"User {self.attack_user} not exists in List of Applications Users")

                        else:
                            self.app_active_session= app_session = requests.Session()
                            app_session_status= "success"
                            

                        #If Session Creation for User is Success 
                        if app_session_status=="success":
                            #All the login calls are completed, Now we can check 
                            self.log.info(f"Success: Session for Application Authentication Created for user {self.attack_user}")
                            self.log.info(f"Fetching crawled URLs for user(s) {self.attack_users['attack']['users']} with application {self.application_id}")

                            self.get_url_payload_list()
                            status= self.get_url_fuzzy_parameters() #Contains attacking operation

                            if status== "paused":
                                return "paused"

                            self.log.info(f"Closing the Session for Application Authentication on user {self.attack_user}")
                            self.app_active_session.close()

                        #If Session Creation for User is Failed.
                        else:
                            self.log.critical(f"Aborting attack operation! Failed to create Session for App. Authentication On user: {self.attack_user}")
                            
                            self.Update_Attack_status(attack_state= 'aborted: AppAuth_Session_Failed',detail_state='attack_aborted')
                            return 'AppAuth_Session_Failed'
                    
                    self.Update_Attack_status(attack_state= 'completed',detail_state='attack_completed')
                    self.log.info(f"All the payloads been fired. Cooling for 300 seconds")
                    time.sleep(20)
                    self.log.info(f"Investigating incidents")

                    status = self.investigate()
                    # status = 'investigation_success'
                    if status == 'investigation_success':
                        self.log.info(f"Generating report")
                        self.reporting()
                    elif status=="ae_logs_not_found":
                        self.log.critical(f"Aborting Reporting operation! AE Logs are not found in Local Dir.")
                        self.Update_Attack_status(attack_state= '',detail_state='report_aborted: AE_Logs_Not_Found')
                        return 'ae_logs_not_found'
                    else:
                        self.log.error(status)
                        return status

                    # else:
                    #     self.log.info(f"App.Authentication login property for Application {self.application_id} is false ")

                    
                # attack_ready is false, Not ready to attack.
                else:
                    self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")

                    self.Update_Attack_status(attack_state= 'aborted: instances_not_normal',detail_state='attack_aborted')
                    return 'instances_not_normal'
            else:
                self.log.warning(f'Application services not available in database')
                self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")

                self.Update_Attack_status(attack_state= 'aborted: services_not_found',detail_state='attack_aborted')
                return 'services_not_found'
        finally:
            # if cache_channel:
            #     cache_channel.close()
            if db_channel:
                db_channel.close()

#Get all URLs of  User
    def get_url_payload_list(self):
        try:
            db_field = dict()
            db_field[f'urls.{self.attack_user}'] = True

            self.log.info(f"Creating complete list of URLs with parameters")
            urls = list()
            url_store = self.mongo.find_document(self.url_store, {'application_id': self.application_id}, db_field)
            for k1, v1 in url_store['urls'].items():
                for k2, v2 in v1.items():
                    for k3, v3 in v2.items():
                        if v3['exercisable_parameters']:  #revisit samit,aj
                            v3['url_id']= k3
                            urls.append(v3)

                            self.service_name= k2

            attack_detail = self.mongo.find_document(self.app_store, {'application_id': self.application_id}, {'attack': True})

            if attack_detail['attack']['payload_policy'].lower() in ['low', 'medium', 'high']:
                self.log.info(f"Creating complete list of Payloads with intensity- low")
                pls = list()
                payload_store = self.mongo.find_all_documents(self.payload_store)
                supported_vulnerabilities= list()
                for vul in payload_store:
                    vul.pop('_id')
                    supported_vulnerabilities.append(list(vul.keys())[0])
                    for vulnerability, payload in vul.items():
                        if vulnerability in was.was['supported_vulnerabilities']:
                            payload_data = list()
                            
                            for data in payload:
                                if data['payload_data']:
                                    payload_data.append({data['capec_id']: data['payload_data']})
                            pls.append(payload_data)
            payloads = [i for i in zip(supported_vulnerabilities, pls)]

            self.url_list= urls
            self.payload_list= payloads
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()   
        return "success"

    def get_url_fuzzy_parameters(self):
        http_session = self.app_active_session
        for p in self.payload_list:       #Looping vulnerabilities or payload types
            try:
                for url in self.url_list:  #Looping all the URLS
                    try:
                        if url['requestType'].upper() == 'GET' and url['parameters']: 
        
                            attack_map = dict()
                            attack_map['session'] = http_session
                            attack_map['method'] = url['requestType'].upper()
                            attack_map['url'] = list()
                            attack_map['url_id'] = url['url_id']
                            attack_map['payload'] = None
                            attack_map['vulnerability'] = p[0]
                            attack_map['service'] = self.service_name
        
                            parent_url = f"{self.auth_details['authentication']['homepage_url']}{url['attack_url']}?"
                            #parent_url = f"{url['attack_url']}?"
                            for k, v in url['parameters'].items():  #Looping parameters in each URL
                                for data in p[1]:            #Looping each payload in a each vulerability
                                    for capec_id, payload in data.items():        #ignore just accessing the dict
                                        if len(url['parameters']) == 1:
                                            attack_map['url'].append({capec_id: f"{parent_url}{k}={payload}"})
                                        elif len(url['parameters']) > 1:
                                            param = str()
                                            for k1, v1 in url['parameters'].items():  #Create query string for fuzzy parameters
                                                if k1 != k:
                                                    # param = f"&{param}{k1}={v1}&"
                                                    param = f"{param}{k1}={v1}&"
                                            attack_map['url'].append({capec_id: f"{parent_url}{k}={payload}&{param}"[:-1]})

                            status= self.attacker(request=attack_map)
                            if status== "paused":
                                return "paused"
        
                        elif url['requestType'].upper() == 'POST' and url['parameters']:
        
                            attack_map = dict()
                            attack_map['session'] = http_session
                            attack_map['method'] = url['requestType'].upper()
                            attack_map['url'] = f"{self.auth_details['authentication']['homepage_url']}{url['attack_url']}"
                            attack_map['url_id'] = url['url_id']
                            attack_map['payload'] = list()
                            attack_map['vulnerability'] = p[0]
                            attack_map['service'] = self.service_name
        
                            for k, v in url['parameters'].items():
                                for data in p[1]:
                                    for capec_id, payload in data.items():
                                        if len(url['parameters']) == 1:
                                            attack_map['payload'].append({capec_id: {k: payload}})
                                        elif len(url['parameters']) > 1:
                                            param = dict()
                                            for k1, v1 in url['parameters'].items():
                                                if k1 != k:
                                                    param[k1] = v1
                                                else:
                                                    param[k] = payload
                                            attack_map['payload'].append({capec_id: param})
        
                            status= self.attacker(request=attack_map)
                            if status== "paused":
                                return "paused"

                    except Exception as err:
                        self.log.error(err)
                        traceback.print_stack(err)
            except Exception as err:
                self.log.error(err)
                traceback.print_stack()
        return "success"

    #Attacks One URL with all fuzzed parameters under one vulnerability.
    def attacker(self, **kwargs):
        http_request = kwargs.get('request')
        cache_channel = self.redis.connect(host=was.was['cache'])

        try:
            header, http_snippet = dict(), list()
            if http_request['method'] == 'GET':
                self.log.info(f"Firing URLs {http_request['url']} with vulnerability {http_request['vulnerability']}")
                
                for url in http_request['url']:
                    try:
                        for capec_id, furl in url.items():
                            try:
                                #Check if Pause is encountered.
                                # cache_attack_data= cache_channel.hmget('attack', self.application_id) #chg
                                cache_attack_data = util.ConvertData((cache_channel.hmget('attack', self.application_id)[0]).decode('utf-8')).framework_compatible()

                                if cache_attack_data['attack_state'] ==  "paused" :
                                    self.log.critical(f"attack operation Paused. at Request Number: {self.count}")
                                    self.Update_Attack_status(attack_state= 'paused',detail_state='attack_paused')
                                    return "paused"

                                else:                                
                                    self.count += 1
                                    if self.count > self.attack_pause_request_count:
                                        self.log.info(f"Generating WAS header for {furl} | request{self.count}")
                                        header['virsec-uid'] = f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}"

                                        response = http_request['session'].request(method=http_request['method'], url=furl, data=http_request['payload'], headers=header, cookies=None, verify=False)

                                        cache_map = dict()
                                        cache_map['request_id'] = f"request{self.count}"
                                        cache_map['uid'] = header['virsec-uid']
                                        cache_map['method'] = http_request['method']
                                        cache_map['url'] = furl
                                        cache_map['vulnerability'] = http_request['vulnerability']
                                        cache_map['service'] = http_request['service']
                                        cache_map['response'] = response.status_code #'test'  #chg
                                        cache_channel.hset(self.application_id, f"request{self.count}", str(cache_map))
                                        cache_channel.hset(self.application_id, f"request{self.count}_payload", str(http_request['payload']))
                                        # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                                    else:
                                        self.log.info(f"Ignoring already attacked Request Number: {self.count} ")
                                        continue
                            
                            except Exception as err:
                                self.log.error(err)
                                traceback.print_stack(err)

                    except Exception as err:
                        self.log.error(err)
                        traceback.print_stack(err)

            elif http_request['method'] == 'POST':
                self.log.info(f"Firing payload {http_request['payload']} from {http_request['vulnerability']} to URL {http_request['url']}")
                try:
                    for payload in http_request['payload']:
                        try:
                            for capec_id, data in payload.items():

                                # cache_attack_data= cache_channel.hmget('attack', self.application_id) #chg
                                cache_attack_data = util.ConvertData((cache_channel.hmget('attack', self.application_id)[0]).decode('utf-8')).framework_compatible()

                                if cache_attack_data['attack_state'] ==  "paused" :
                                    self.log.critical(f"attack operation Paused. at Request Number: {self.count}")
                                    self.Update_Attack_status(attack_state= 'paused',detail_state='attack_paused')
                                    return "paused"

                                else:       
                                    self.count += 1
                                    if self.count > self.attack_pause_request_count:                         
                                        self.log.info(f"Generating WAS header for url {http_request['url']} | request{self.count}")
                                        header['virsec-uid'] = f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}"

                                        response = http_request['session'].request(method=http_request['method'], url=http_request['url'], data=data, headers=header, cookies=None, verify=False)

                                        cache_map = dict()
                                        cache_map['request_id'] = f"request{self.count}"
                                        cache_map['uid'] = header['virsec-uid']
                                        cache_map['method'] = http_request['method']
                                        cache_map['url'] = http_request['url']
                                        cache_map['vulnerability'] = http_request['vulnerability']
                                        cache_map['service'] = http_request['service']
                                        cache_map['response'] = response.status_code  #chg
                                        cache_channel.hset(self.application_id, f"request{self.count}", str(cache_map))
                                        cache_channel.hset(self.application_id, f"request{self.count}_payload", str(data))
                                        # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                                    else:
                                        self.log.info(f"Ignoring Request Number: {self.count}")
                                        continue

                        except Exception as err:
                            self.log.error(err)
                            traceback.print_stack(err)

                except Exception as err:
                    self.log.error(err)
                    traceback.print_stack(err)

        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)

        self.log.info(f"Payload Combination {http_request['vulnerability']} and URL {http_request['url']} has been considered as part of Attack")
        return "success"

        # finally:
        #     self.log.info(f"Attack completed : on  Payload Combination {http_request['vulnerability']} and URL {http_request['url']}")
        #     return "success"

            # if cache_channel:
            #     cache_channel.close()

    def app_Validation(self):
        cache_channel = self.redis.connect(host=was.was['cache'])
        for self.attack_user,attack_user_data in self.attack_users['attack']['users'].items():  #Looping all users.
            try:
                if self.attack_user in self.users_login_calls:   
                    self.log.info("Application Auth Validation Initiated for user: ", self.attack_user)
                    app_user_validation= "failure"

                    for login_call in self.users_login_calls[self.attack_user]["http_stream"]:     #loop thru all calls
                        if login_call["method"]== "POST" and "requestBody" in login_call:

                            app_session = requests.Session()
                            response = app_session.post(url=login_call['url'], data=login_call['requestBody'])
                            if response.status_code == 200:
                                app_user_validation= "success"
                                app_session.close()
                            else:
                                app_session.close()
                    if app_user_validation=="success":
                        self.log.info(f"Application Validation Success for User {self.attack_user}")
                    else:
                        self.log.info(f"Application Validation Failed for User {self.attack_user}")
                        self.log.info(f"Application Validation Failed for Application {self.application_id}")

                        self.log.critical(f"Aborting attack operation! Failed to Validate App. Authentication")
                        self.Update_Attack_status(attack_state= 'aborted: AppAuth_validation_Failed',detail_state='attack_aborted')

                        return 'failure'
            except Exception as err:
                self.log.error(err)
                traceback.print_stack(err)
                self.log.critical(f"Aborting attack operation! Failed to Validate App. Authentication")
                self.Update_Attack_status(attack_state= 'aborted: AppAuth_validation_Failed',detail_state='attack_aborted')
                return 'failure'

        self.log.info(f"Application Validation Success for Application {self.application_id}")
        return 'success'
        
    def Update_Attack_status(self, attack_state= "",detail_state= ""):
        end_time = time.time()
        # cache_channel.hset(self.application_id, 'attack_state', attack_state)#'aborted: services_not_found')

        if detail_state== "attack_aborted":
            self.mongo.update_document(self.app_store, {'$set': {'attack.attack_state': attack_state,
                                                        'attack.attack_aborted': end_time}},  {'application_id': self.application_id}, upsert=True)
            self.mongo.update_document(self.app_store, {'$set': {'detail.state': detail_state}},
                                        {'application_id': self.application_id}, upsert=True)
        
        elif detail_state== "attack_completed":
            self.mongo.update_document(self.app_store, {'$set': {'attack.attack_state': attack_state,
                                                        'attack.attack_completed': end_time}},
                                        {'application_id': self.application_id}, upsert=True)
            self.mongo.update_document(self.app_store, {'$set': {'detail.state': detail_state}},
                                        {'application_id': self.application_id}, upsert=True)

        elif detail_state== "report_ready": 
            self.mongo.update_document(self.app_store, {'$set': {'attack.attack_state': attack_state}},
                                        {'application_id': self.application_id}, upsert=True)
            self.mongo.update_document(self.app_store, {'$set': {'detail.state': detail_state}},
                                        {'application_id': self.application_id}, upsert=True)

        elif detail_state== "report_aborted: AE_Logs_Not_Found": 
            self.mongo.update_document(self.app_store, {'$set': {'detail.state': detail_state}},
                                        {'application_id': self.application_id}, upsert=True)
        elif detail_state== "attack_paused": 
            self.mongo.update_document(self.app_store, {'$set': {'attack.attack_state': attack_state,
                                                                 'attack.attack_paused': end_time,
                                                                 'attack.attack_pause_request_count': self.count}},  
                                                                 
                                                                 {'application_id': self.application_id}, upsert=True)
            self.mongo.update_document(self.app_store, {'$set': {'detail.state': detail_state}},
                                        {'application_id': self.application_id}, upsert=True)        
        else:
            self.log.info("Unexpected Scenario Found.")

        # status = self.mongo.update_document(self.app_store, {'$set': {'attack.attack_AE_Request_Count': self.count}},
        #                     {'application_id': self.application_id}, upsert=True)

    def parse_log(self, log_path):
        #Add UUID values to a list
        try:
            f = open(log_path, 'r')
            line_nums = []
            search_phrase1 = "ActiveMQ_Mgr::send: JSON: (MsgSeq#"
            search_phrase2 = "Dest: DBI-CMS-QUEUE): {"  #"Dest: SW-EXC-LOG-QUEUE"
            
            line_num= 0
            for line in f.readlines():
                line_num += 1
                if (line.find(search_phrase1) >= 0) and line.find(search_phrase2) >= 0:
                    line_nums.append(line_num)#print line_num
                    
            f = open(log_path, 'r')
            line_data= f.readlines()
            uuids=[]
            tables= []
            threatscores=[]
            levels=[]
            threat_descs= []
            RequestIds= []
            virsec_uids= []
            for index,line in enumerate(line_nums):
                temp_uuid= None
                temp_virsecuid= ""
                #Iterate to the next line until i find uuid
                for loopline in range(1+line, 1+line+50):
                    linevalue= (line_data[loopline])
                    
                    if "ActiveMQ_Mgr::send: JSON: (MsgSeq" in linevalue:
                        break
                    if linevalue.strip()=="}":
                        break
                    
                    if "Table" in linevalue:
                        temp= (linevalue.strip(",").strip().split(":"))[1]
                        temp = temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        tables.append(temp)

                    if "threatscore" in linevalue:
                        temp= (linevalue.strip(",").strip().split(":"))[1]
                        temp = temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        threatscores.append(temp)#((linevalue.strip(",").strip().split(":"))[1])

                    if "uuid" in linevalue:
                        temp_uuid= (linevalue.strip(",").strip().split(":"))[1]
                        temp_uuid = temp_uuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        uuids.append(temp_uuid)

                    if "level" in linevalue:
                        temp= (linevalue.strip(",").strip().split(":"))[1]
                        temp = temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        levels.append(temp)

                    if "threat_desc" in linevalue:
                        temp= (linevalue.strip(",").strip().split(":"))[1]
                        temp = temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        threat_descs.append(temp)

                    if "RequestId" in linevalue:
                        temp= (linevalue.strip(",").strip().split(":"))[1]
                        temp = temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        RequestIds.append(temp)

                    if "virsec-uid" in linevalue:
                        temp_virsecuid= (linevalue.strip(",").strip().split(":"))[1]
                        temp_virsecuid = temp_virsecuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        # virsec_uids.append(temp_virsecuid)
                    
                    # if temp_virsecuid!="":
                        
                virsec_uids.append(temp_virsecuid)


            log_map= dict()
            self.uuids= uuids
            for num, value in enumerate(uuids):
                if virsec_uids[num]!="":
                    request_num= int((virsec_uids[num].split('#')[5]).replace("request",""))
                    if request_num > 0 :
                        # self.log.info(f"Adding request Number {request_num} due to Initial count Initial_Request_Count {self.Initial_Request_Count}")
                        log_map[value]= {"level": levels[num],
                                        "table": tables[num],
                                        "threatscore": threatscores[num],
                                        "threat_desc": threat_descs[num],
                                        "RequestId": request_num, #virsec_uids[num].split('#')[5], #RequestIds[num],
                                        "virsec_uid": virsec_uids[num]}
                    # else:
                    #     self.log.info(f"Ignoring request Number {request_num} due to Initial count Initial_Request_Count {self.Initial_Request_Count}")
            self.log.info(f"Found {len(log_map)} UUID values in Log")
            self.uuids= list(log_map.keys())

            #
            return log_map
        except Exception as err:
            self.log.info(err)

    def investigate(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')

            cms = util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            access_token = fw.CMS(cms['ipv4_address']).token_status()
            cms_services_header = util.Authentication().create_http_header('services', access_token, cms['ipv4_address'])

            application_ae = fw.CMS(cms['ipv4_address']).application_analysis_engine(self.application_id, cms_services_header)
            application_ae_address = application_ae[0]['serverNetworkInfo']['ipAddress']

            #Status shud be normal for that AE.  #CHG Needed
            if application_ae_address:
                coll = self.mongo.create_collection(db, 'vault')
                doc = self.mongo.find_document(coll, {'username': cms['username']})
                cms_password = util.Authentication().decrypt_password(key=doc['key'], encrypted_password=doc['password'])


                if "nt" in os.name:
                    local_dir = f"G:/emejson.log" #f"/tmp/artefacts/traces/ae/{self.application_id}.log"
                else:
                    local_dir = f"/tmp/emejson.log" #f"/tmp/artefacts/traces/ae/{self.application_id}.log"

                ae_dir = f"/var/virsec/log/emejson.log" #f"/var/tmp/ae.txt"

                cms_username= "virsec"
                # cms_password= "P@ssword1"
                # establish ssh connection between your local machine and the jump server
                cms_session = SSHSession(cms['ipv4_address'],cms_username, password=cms_password).open()
                ae_session = cms_session.get_remote_session(application_ae_address,password=cms_password)
                ae_session.get(ae_dir, local_dir, use_sudo=True)
                ae_session.close()
                cms_session.close()

                os.stat(local_dir)
                if os.path.exists(local_dir):

                    log_map= self.parse_log(local_dir)
                    cms_incidents = fw.CMS(cms['ipv4_address']).application_incidents(self.application_id,
                                                                                        cms_services_header)
                    cms_incident_ids = list()
                    for incident in cms_incidents:
                        cms_incident_ids.append(incident['id'])                

                    known_incidents = dict()
                    for incident in cms_incident_ids:
                        incident_detail = fw.CMS(cms['ipv4_address']).application_incident_detail(self.application_id,
                                                                                                    cms_services_header, incident)
                        for log_uid in self.uuids: #, virsec_uid in uid_map.items():
                            if incident_detail['details']['attributes']['Threat Level'] in ['ATTACK', 'THREAT'] and incident_detail['details']['attributes']['UUID'] == log_uid:
                                incident_map = dict()

                                virsec_uid= log_map[log_uid]['virsec_uid']
                                incident_map[log_uid]= dict()
                                incident_map[log_uid]['uid'] = log_uid

                                incident_map[log_uid]['capec_id'] = virsec_uid.split('#')[4]
                                incident_map[log_uid]['request_id'] = virsec_uid.split('#')[5]
                                incident_map[log_uid]['service'] = virsec_uid.split('#')[6]
                                incident_map[log_uid]['method'] = virsec_uid.split('#')[7]


                                incident_map[log_uid]['uri'] = incident_detail['details']['attributes']['HTTP Request']#.split(' ')[1]
                                incident_map[log_uid]['url_id'] = virsec_uid.split('#')[2]
                                incident_map[log_uid]['vulnerability'] = virsec_uid.split('#')[3]
                                incident_map[log_uid]['level'] = log_map[log_uid]['level']

                                known_incidents.update(incident_map)
                            else:
                                continue
                    
                    status = cache_channel.hset(self.application_id, 'known_incidents', str(known_incidents))                    
                    if status == 0:
                        return 'investigation_success'
                
                else: # AE logs not available
                    self.log.critical(f"Analysis Engine logs not available")
                    return 'ae_logs_not_found'
            else:
                self.log.critical("Unable to find analysis engine address")
                return 'analysis_engine_not_available'
        
        except Exception as err:
            self.log.info(err)
            traceback.print_stack(err)

        finally:
            if db_channel:
                db_channel.close()

    def reporting(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')

            app_store = self.mongo.create_collection(db, 'applications')
            app_data = self.mongo.find_document(app_store, {'application_id': self.application_id})

            url_store_coll = self.mongo.create_collection(db, 'url_store')
            url_store = self.mongo.find_document(url_store_coll, {'application_id': self.application_id})
            known_incidents = util.ConvertData(cache_channel.hget(self.application_id, 'known_incidents').decode('utf-8')).framework_compatible()

            all_vulnerabilities = dict()
            for incident_uid, incident_details in known_incidents.items():
                request_details = util.ConvertData(cache_channel.hget(self.application_id, incident_details['request_id']).decode('utf-8')).framework_compatible()
                request_payload = cache_channel.hget(self.application_id, f"{incident_details['request_id']}_payload").decode('utf-8')

                vulnerabilities = dict()
                vulnerabilities[request_details['request_id']] = dict()
                vulnerabilities[request_details['request_id']]['request_id'] = request_details['request_id']
                vulnerabilities[request_details['request_id']]['uid'] = request_details['uid']
                vulnerabilities[request_details['request_id']]['method'] = request_details['method']
                vulnerabilities[request_details['request_id']]['url'] = request_details['url']
                vulnerabilities[request_details['request_id']]['payload'] = request_payload
                vulnerabilities[request_details['request_id']]['response'] = request_details['response']
                vulnerabilities[request_details['request_id']]['vulnerability'] = request_details['vulnerability']
                vulnerabilities[request_details['request_id']]['url_id'] =  incident_details['url_id']
                vulnerabilities[request_details['request_id']]['capec_id'] = incident_details['capec_id']
                # vulnerabilities[request_details['request_id']]['capec_id'] = incident_details['capec_id']
                vulnerabilities[request_details['request_id']]['service'] = request_details['service']
                vulnerabilities[request_details['request_id']]['level'] = incident_details['level']
                all_vulnerabilities.update(vulnerabilities)


            report = dict()

            report['report_id'] = util.Authentication().generate_uuid('uuid4')
            report['report_name'] = f"{app_data['detail']['name']}_{app_data['detail']['version']}"
            report['report_version'] = "1.0.0"

            report['application_id'] = self.application_id
            report['application_details'] = dict()
            report['application_details']['application_id'] =self.application_id
            report['application_details']['application_name'] = app_data['detail']['name']
            report['application_details']['application_version'] = app_data['detail']['version']
            report['application_details']['application_url'] = url_store['authentication']['homepage_url']
            report['application_details']['application_user'] = ''
            report['application_details']['scan_start_time'] = app_data['attack']['attack_instantiated']
            report['application_details']['scan_complete_time'] = app_data['attack']['attack_completed']
            report['application_details']['user_email'] = 'was_admin@virsec.com'
            report['application_details']['was_isntance'] = util.Network().get_ipv4()
            report['vulnerability_distribution']= dict()
            report['vulnerability_distribution']['severity']= dict()

            report['vulnerability_distribution']['severity']["CRITICAL"]= 0
            report['vulnerability_distribution']['severity']["HIGH"]= 0
            report['vulnerability_distribution']['severity']["MEDIUM"]= 0
            report['vulnerability_distribution']['severity']["LOW"]= 0
            report['vulnerability_distribution']['severity']["INFO"]= 0


            report['services'] = dict()
            for rid, rdetails in all_vulnerabilities.items():
                #If this is new service. Add a service
                if rdetails['service'] not in report['services'] :
                    report['services'][rdetails['service']] = dict()
                    report['services'][rdetails['service']]['vulnerabilities'] = dict()

                #If this is new vulnerability, Add a vulnerability
                if rdetails['vulnerability'] not in report['services'][rdetails['service']]['vulnerabilities'] :
                    vuls= report['services'][rdetails['service']]['vulnerabilities'] #dict()
                    vuls[rdetails['vulnerability']] = dict()
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']= dict()
                    vuls[rdetails['vulnerability']]['recommendations'] = dict()
                    vuls[rdetails['vulnerability']]['references'] = dict()
                    vuls[rdetails['vulnerability']]['risk_factor'] = 'critical'
                    vuls[rdetails['vulnerability']]['urls'] = dict()

                    vuls[rdetails['vulnerability']]['vulnerability_id'] = rdetails['vulnerability']
                    vuls[rdetails['vulnerability']]['vulnerability_name'] = rdetails['vulnerability']
                    vuls[rdetails['vulnerability']]['affected_items'] = 0
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']['capec']= dict()
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']['cwe'] = dict()
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']['owasp'] = dict()
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']['sans'] = dict()
                    vuls[rdetails['vulnerability']]['vulnerability_classifications']['cvss'] = dict()
                    report['services'][rdetails['service']]['vulnerabilities'] = vuls #dict()

                report['services'][rdetails['service']]['vulnerabilities'][rdetails['vulnerability']]['affected_items'] += 1 #len(temp)
                severity= self.generate_cvss_severity(rdetails['vulnerability'], rdetails['level'] )
                report['vulnerability_distribution']['severity'][severity.upper()]+= 1

                Present_vulnerability= report['services'][rdetails['service']]['vulnerabilities']
                Present_vulnerability[rdetails['vulnerability']]['urls'][rdetails['url_id']]= dict()
                Present_vulnerability[rdetails['vulnerability']]['urls'][rdetails['url_id']]['request_type'] = rdetails['method']
                Present_vulnerability[rdetails['vulnerability']]['urls'][rdetails['url_id']]['url'] = rdetails['url']
                Present_vulnerability[rdetails['vulnerability']]['urls'][rdetails['url_id']]['url_id'] = rdetails['url_id']

                Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['capec'][rdetails['capec_id']] = dict()
                Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['capec'][rdetails['capec_id']]["capec_id"] = rdetails['capec_id']
                Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['capec'][rdetails['capec_id']]["capec_description"] = "Capec_description" #rdetails['capec_description']                # Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['capec'][i['capec_id']]['capec_id'] = i['capec_id']
                
                #check if cwe mapping exists
                if rdetails['capec_id'] in was.was['capec_cwe_mapping']:
                    cwe_id = was.was['capec_cwe_mapping'][rdetails['capec_id']]
                    
                    if cwe_id in was.was['cwe_id_desc']:
                        Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['cwe'][str(cwe_id)] = dict()
                        Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['cwe'][str(cwe_id)]["cwe_id"] = cwe_id
                        Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['cwe'][str(cwe_id)]["cwe_description"] = was.was['cwe_id_desc'][cwe_id]

                report['services'][rdetails['service']]['vulnerabilities']= Present_vulnerability


            report_coll = self.mongo.create_collection(db, 'reports')
            app_data = self.mongo.find_document(report_coll, {'application_id': self.application_id})
            if app_data!="document_not_found":
                self.log.info("Found existing report in database")
                report_coll.delete_one( { "application_id": self.application_id })
                self.log.info("Removed existing report in database")

            status = self.mongo.insert_document(report_coll, report)

            if status == 'insert_success':
                self.log.info(f"Report successfully generated")
                self.Update_Attack_status(attack_state= 'completed',detail_state='report_ready')

                return 'attack_complete_successful'
            else:
                self.log.critical(f"Report could not successfully generated")
                return status
        
        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)
            return 'failure'
        finally:
            if db_channel:
                db_channel.close()

    def generate_cvss_severity(self,current_vul_type,threat):
        try:

            cvss_base_score_dict= was.was["cvss_base_score_dict"]
            av = cvss_base_score_dict['Attack Vector']
            ac = cvss_base_score_dict['Attack Complexity']
            pr = cvss_base_score_dict['Privileges Required']
            ui = cvss_base_score_dict['User Interaction']
            a = cvss_base_score_dict['Availability Impact']
            # s = cvss_base_score_dict['Scope']
            # c = cvss_base_score_dict['Confidentiality Impact']
            # i = cvss_base_score_dict['Integrity Impact']
            if 'sqli' in current_vul_type :
                s = "S:C"
                i = "I:H"
                c = "C:H"
            elif 'cmdi' in current_vul_type:
                s = "S:C"
                i = "I:H"
                c = "C:H"
            elif 'pathtraversal' in current_vul_type :
                s = "S:U"
                i = "I:L"
                c = "C:H"
            else:
                s = "S:U"
                i = "I:L"
                c = "C:H"
            cvss_base_vector = "CVSS:3.0/{}/{}/{}/{}/{}/{}/{}/{}".format(av,ac,pr,ui,s,c,i,a)
            c = CVSS3(cvss_base_vector)
            cvss_score = c.scores()[0]
            if threat== "THREAT":
                cvss_score= (cvss_score + (cvss_score-1.5))/2
            
            
            cvss_severity = ""
            if 0.1 <= cvss_score <= 3.9:
                cvss_severity = "Low"

            elif 4.0 <= cvss_score <= 6.9:
                cvss_severity = "Medium"

            elif 7.0 <= cvss_score <= 8.9:
                cvss_severity = "High"

            elif 9.0 <= cvss_score <= 10.0:
                cvss_severity = "Critical"
            else:
                cvss_severity = "Critical"      
            
            return cvss_severity
        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)
        traceback.print_exc()