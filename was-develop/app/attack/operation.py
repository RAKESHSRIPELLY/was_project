# from webapp.operations.routes import attack_status
from redis.connection import SYM_DOLLAR
from requests import exceptions
from lib import utility as util,framework as fw
from config import was,environment as env
import time
import requests
from urllib.parse import quote
import os
import traceback
import json
from json import loads,dumps
# from requests.utils import quote
from multiprocessing import Process,Pipe
from multiprocessing.pool import ThreadPool
from jumpssh import SSHSession, exception
from cvss import CVSS2,CVSS3
import urllib.parse as urlparse
from urllib.parse import parse_qs
###MEM_TEST###
from copy import deepcopy,copy
# from memory_profiler import profile
import gc
from lib import widget as dash
import re
import base64
from http import client
# from zlib import compress, decompress
from datetime import timedelta,datetime,timezone
import uuid
from time import sleep


##############

class Attack:

    def __init__(self,application_id):
        self.application_id=application_id
        self.app_name=""
        self.log=util.Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()
        self.cache_channel=None
        self.count=0
        self.cms=None
        self.cms_not_ok=False
        self.report_start_time=0
        self.attack_start_time=int(datetime.now(tz=timezone.utc).timestamp()*1000)
        self.max_count=0
        self.service_name=[]
        self.request_exception_reason=""
        
    def initiate(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.cache_channel=cache_channel
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            report_generation=True
            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            self.cms=fw.CMS(cms['ipv4_address'])
            self.app_store=self.mongo.create_collection(db,'applications')
            self.url_store=self.mongo.create_collection(db,'url_store')
            applications=self.mongo.find_document(self.app_store,{'application_id':self.application_id})
            self.payload_policy=applications['attack']['payload_policy'] if (
                applications['attack']['payload_policy']) else "low"
            payload_db_name=was.configuration['payload_policy'][self.payload_policy.lower()]
            self.payload_store=self.mongo.create_collection(db,payload_db_name)
            self.attack_instantiate=applications['attack']['attack_instantiated']
            self.attack_instantiate_timestamp=datetime.fromtimestamp(self.attack_instantiate,tz=timezone.utc)

            app_data=self.mongo.find_document(self.app_store,{'application_id':self.application_id})
            self.app_name=app_data['detail']['name']
            # self.count= app_data['attack']['attack_AE_Request_Count']
            self.Initial_Request_Count=self.count
            # self.log.info(f"Resuming the Request Count from Past Request Count of AE : {self.count}")
            self.error_urls=[]
            self.auth_details=self.mongo.find_document(self.url_store,{'application_id':self.application_id},
                {'authentication':True})
            self.app_auth_details=self.auth_details['authentication']['application_authentication']
            self.fw_auth_details=self.auth_details['authentication']['framework_authentication']
            self.log.info(f"Validating if application instance(s) is in appropriate state")

            #  Get all instances of an Application ID
            application_services=self.mongo.find_document(self.url_store,{'application_id':self.application_id},
                {'services':True})
            self.Update_Attack_status(redis_update="in_progress",attack_state='in_progress',detail_state='attacking')
            if 'services' in application_services:
                application_instances=set()
                for k,v in application_services['services'].items():
                    for instance in v['instances']:
                        application_instances.add(instance)
                self.log.info(f"App instances are : {application_instances}")

                #   Get all CMS Instances,
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()

                access_token=self.cms.token_status()
                cms_services_header=util.Authentication().create_http_header('services',access_token,
                    cms['ipv4_address'])
                cms_application_instances=self.cms.application_instances(self.application_id,cms_services_header)
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
                # Murali Change: Stale state
                ###########################
                if cms_application_instances not in ['invalid_application','connection_error',None]:
                    ###########################
                    attack_ready=False
                    for instance in application_instances:
                        for app_instance in cms_application_instances:
                            # application_status, application_name = fw.CMS(cms['ipv4_address']).application_status_v1(self.application_id,cms_services_header,access_token)

                            if instance==app_instance['serverNetworkInfo'][
                                'ipAddress']:  # and app_instance['status'] in ['NORMAL', 'THREAT', 'ATTACK']: #'PROVISIONED':  #chg
                                # if instance == app_instance['ipAddress'] and app_instance['state'] in ['NORMAL', 'THREAT', 'ATTACK']: #'PROVISIONED':  #chg
                                attack_ready=True
                                # self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['state']} state")
                                break
                            else:
                                attack_ready=False
                                # self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['state']} state")

                        if attack_ready==True:
                            break

                    if attack_ready==True:
                        self.log.info(f"Validating application authentication for application- {self.application_id}")

                        self.attack_users=self.mongo.find_document(self.app_store,
                            {'application_id':self.application_id},
                            {'attack.users':True})
                        for k,v in self.attack_users['attack']['users'].items():
                            user=k
                            self.current_attack_user=v['username']

                        if self.app_auth_details['login']==True and user!='user_0':
                            app_validation_status=self.app_Validation()
                        else:
                            app_validation_status="success"

                        if app_validation_status!="success":
                            self.log.info(f"Application Authentication validation Failed")
                            return 'AppAuth_validation_Failed'

                        # Loop through Users and create sesssions
                        # if self.app_auth_details['login'] == True :
                        for self.attack_user,attack_user_data in self.attack_users['attack'][
                            'users'].items():  # Looping all users.
                            app_session_status="Failure"

                            if self.app_auth_details['login']==True and user!='user_0':
                                self.users_login_calls=self.app_auth_details["users"]
                                if self.attack_user in self.users_login_calls:
                                    self.log.info(f"User {self.attack_user} exists in both Attack List and Login List")

                                    #   Looping through all Login calls http_streams
                                    for login_call in self.users_login_calls[self.attack_user]["http_stream"]:
                                        if login_call["method"]=="POST" and "requestBody" in login_call:
                                            self.log.info(
                                                f"Application call has been made for user: {self.attack_user} for requestID:  {login_call['requestId']} ")

                                            # Create a new session
                                            app_session=requests.Session()
                                            response=app_session.post(url=login_call['url'],
                                                data=login_call['requestBody'])
                                            if response.status_code==200:
                                                self.app_active_session=app_session
                                                app_session_status="success"

                                            else:
                                                app_session.close()
                                else:
                                    self.log.info(f"User {self.attack_user} not exists in List of Applications Users")

                            else:
                                self.app_active_session=app_session=requests.Session()
                                app_session_status="success"

                            # If Session Creation for User is Success
                            if app_session_status=="success":
                                # All the login calls are completed, Now we can check
                                self.log.info(
                                    f"Success: Session for Application Authentication Created for user {self.attack_user}")
                                self.log.info(
                                    f"Fetching crawled URLs for user(s) {self.attack_users['attack']['users']} with application {self.application_id}")
                                # Murali Change: Stale state
                                ###########################
                                if self.get_url_payload_list():
                                    ###########################
                                    report_generation=self.get_url_fuzzy_parameters()  # Contains attacking operation for url
                                    report_generation&=self.fuzzy_header()  # Contains attacking operation for header
                                else:
                                    # Murali Change: Stale state
                                    ###########################
                                    self.Update_Attack_status(
                                        redis_update="report_generation",
                                        attack_state='report_generation',
                                        detail_state='aborted',
                                        message=f"Attack operation partially completed for application {self.app_name} due to AppAuth_Session_Failed",
                                        subject=f"Attack partially completed for App: {self.app_name}",
                                        operation="Report"
                                    )

                                self.log.info(
                                    f"Closing the Session for Application Authentication on user {self.attack_user}")
                                self.app_active_session.close()

                            # If Session Creation for User is Failed.
                            else:
                                self.log.critical(
                                    f"Aborting attack operation! Failed to create Session for App. Authentication On user: {self.attack_user}")
                                # Murali Change: Stale state
                                ###########################
                                self.redis.set_status_value(cache_channel,'attack',self.application_id,
                                    attack_state='report_generation')
                                message=f"Attack operation partially completed for application {self.app_name} ({self.application_id}) as application status was found as {app_session_status}"
                                util.Notification().send_notification(message=message,
                                    application_id=self.application_id,
                                    operation='Attack',
                                    application_name=self.app_name)
                                ###########################
                                self.Update_Attack_status(redis_update="report_generation",
                                    attack_state='report_generation',
                                    detail_state='aborted')
                                return 'AppAuth_Session_Failed'
                        ###########################
                        self.log.info(f"All the payloads been fired. Cooling for 20 seconds")
                        time.sleep(20)
                        if report_generation:
                            self.Update_Attack_status(
                                redis_update="report_generation",
                                attack_state='report_generation',
                                detail_state='report_generation')
                            # self.Update_Attack_status(attack_state= 'report_generation',detail_state='report_generation')
                            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='report_generation')
                            status=self.investigate()
                            # status = 'investigation_success'
                            if status=='investigation_success':
                                self.log.info(f"Generating report")
                                self.reporting()
                            elif status=="ae_logs_not_found":
                                self.log.critical(f"Aborting Reporting operation! AE Logs are not found in Local Dir.")
                                self.Update_Attack_status(redis_update="report_generation",
                                    attack_state='report_generation',
                                    detail_state='report_aborted',message=f'ae_logs_not_found')
                                return 'ae_logs_not_found'
                            elif status=="CMS_incidents_empty":
                                self.log.critical(f"Aborting Reporting operation! CMS incidents not registered")
                                return status
                            else:
                                self.log.error(status)
                                return status

                        # else:
                        #     self.log.info(f"App.Authentication login property for Application {self.application_id} is false ")


                    # attack_ready is false, Not ready to attack.
                    else:
                        self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")
                        self.Update_Attack_status(
                            redis_update="report_generation",
                            attack_state='report_generation',
                            detail_state='aborted',
                            message=f"Attack operation partially completed for application {self.app_name} ({self.application_id}) as application was found not ready"
                        )
                        # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                        # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                        message=f"Attack operation partially completed for application {self.app_name} ({self.application_id}) as application was found not ready"
                        util.Notification().send_notification(message=message,
                            application_id=self.application_id,
                            operation='Attack',
                            application_name=self.app_name)
                        return 'instances_not_normal'
                # Murali Change: Stale state
                ###########################
                else:
                    self.Update_Attack_status(
                        redis_update="report_generation",
                        attack_state='report_generation',
                        detail_state='aborted',
                        message=f"Attack operation partially completed for application {self.app_name} as CMS application instance is not normal",
                        subject=f"Attack partially completed for App: {self.app_name}",
                        operation="Attack"
                    )
                    # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                    # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                    # message = f"Attack operation aborted for application {self.app_name} ({self.application_id}) as CMS application instance was set as {cms_application_instances}"
                    # util.Notification().send_notification(message=message,
                    #                                         application_id=self.application_id,
                    #                                         operation='Attack',
                    #                                         application_name=self.app_name)
                ###########################
            else:
                self.log.warning(f'Application services not available in database')
                self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")
                self.Update_Attack_status(
                    redis_update="report_generation",
                    attack_state='report_generation',
                    detail_state='report_aborted',
                    message=f"Attack operation partially completed for application {self.app_name} as application services not available in database ",
                    subject=f"Attack partially completed for App: {self.app_name}",
                    operation="Attack"
                )
                # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                # message = f"Attack operation aborted for application {self.app_name} ({self.application_id})"
                # util.Notification().send_notification(message=message,
                #                                         application_id=self.application_id,
                #                                         operation='Attack',
                #                                         application_name=self.app_name)
                return 'services_not_found'
        except Exception as e:
            # Murali Change: Stale state
            ###########################
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='aborted',
                message=f"Attack operation partially completed for application {self.app_name} as services are not available.",
                subject=f"Attack partially completed for App: {self.app_name}",
                operation="Attack"
            )
            # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
            # message = f"Attack operation aborted for application {self.app_name} ({self.application_id})"
            # util.Notification().send_notification(message=message,
            #                                         application_id=self.application_id,
            #                                         operation='Attack',
            #                                         application_name=self.app_name)
            self.log.critical(f"Aborting attack operation! Exception raised: {e}")
            ###########################
        finally:
            # if cache_channel:
            #     cache_channel.close()
            
            # <---- Removing application request & request_payload Cache on Redis -->
            key_list = []
            for index_count in range(0, self.count+1):
                key_list.append(f"request{index_count}")
                key_list.append(f"request{index_count}_payload")
            cache_channel.hdel(self.application_id, *key_list)
            
            # for index_count in range(0, self.count+1):
            #     cache_channel.hdel(self.application_id, f"request{index_count}")
            #     cache_channel.hdel(self.application_id, f"request{index_count}_payload")
            
            if db_channel:
                db_channel.close()
            gc.collect()

    def get_url_payload_list(self):
        try:
            ###MEM_TEST###
            # db_field = dict()
            db_field={}
            #################
            db_field[f'urls.{self.attack_user}']=True

            self.log.info(f"Creating complete list of URLs with parameters")
            ###MEM_TEST###
            # urls = list()
            urls={}
            self.urlprogress_count=[]
            self.paloadprogress_count=0
            self.header_length=[]
            ##############
            url_store=self.mongo.find_document(self.url_store,{'application_id':self.application_id},db_field)
            for k1,v1 in url_store['urls'].items():
                if k1==self.attack_user:
                    for k2,v2 in v1.items():
                        for k3,v3 in v2.items():
                            self.service_name.append(k2)
                            if v3['exercisable_parameters']:  # revisit samit,aj
                                v3['url_id']=k3
                                if k2 not in urls.keys():
                                    urls[k2]=[]
                                urls[k2].append(v3)
                                self.urlprogress_count.append(len(v3['exercisable_parameters']))
                            if v3['header']:
                                header_length=set(v3['header'].keys())-set(self.get_list_no_header_attack())
                                he_length=len(header_length)
                                self.header_length.append(he_length)

            attack_detail=self.mongo.find_document(self.app_store,{'application_id':self.application_id},
                {'attack':True})

            if attack_detail['attack']['payload_policy'].lower() in ['low','medium','high']:
                self.log.info(f"Creating complete list of Payloads with intensity- low")
                pls=list()
                payload_store=self.mongo.find_all_documents(self.payload_store)
                supported_vulnerabilities=list()
                for vul in payload_store:
                    vul.pop('_id')
                    supported_vulnerabilities.append(list(vul.keys())[0])
                    for vulnerability,payload in vul.items():
                        if vulnerability in was.was['supported_vulnerabilities']:
                            payload_data=list()

                            for data in payload:
                                if data['payload_data']:
                                    decode_data=base64.b64decode(data['payload_data'])
                                    payload_data.append({data['capec_id']:decode_data.decode("ascii")})
                                    self.paloadprogress_count+=1
                            pls.append(payload_data)
            payloads=[i for i in zip(supported_vulnerabilities,pls)]
            ###MEM_TEST###
            # self.url_list= urls
            # self.payload_list= payloads
            self.url_list=copy(urls)
            self.payload_list=copy(payloads)
            del payloads
            del urls
            ##############
            # with open("./list_of_URLs_to_be_fired.txt","a") as f:
            #     f.write("list of URLs to be fired\n")
            #     f.write(str(self.url_list))
            # Murali Change: Stale state
            ###########################
            return True
            ###########################
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return False
        # return ""

    def get_url_fuzzy_parameters(self):
        http_session=self.app_active_session
        self.parameter_list=[]
        # global cms_pool_status
        cache_channel=self.redis.connect(host=was.was['cache'])
        for p in self.payload_list:  # Looping vulnerabilities or payload types
            try:
                for service_name,url_list in self.url_list.items():
                    for url in url_list:  # Looping all the URLS
                        try:
                            # if not self.cms.check_cms_value(application_id=self.application_id, app_name=self.app_name):
                            #     # self.Update_Attack_status(
                            #     #     redis_update="aborted",
                            #     #     attack_state='aborted',
                            #     #     detail_state='aborted',
                            #     #     message="Attack aborting as App status in CMS was not in 'NORMAL'/'THREAT'/'ATTACK'",
                            #     #     subject=f"Attack aborted for App: {self.app_name}"
                            #     # )

                            # else:
                            if url['requestType'].upper()=='GET' and url['parameters']:
                                ###MEM_TEST###
                                # attack_map = dict()
                                attack_map={}
                                ###############
                                attack_map['session']=http_session
                                attack_map['method']=url['requestType'].upper()
                                attack_map['url']=list()
                                attack_map['url_id']=url['url_id']
                                attack_map['payload']=None
                                attack_map['vulnerability']=p[0]
                                attack_map['service']=service_name

                                # parent_url = f"{self.auth_details['authentication']['homepage_url']}{url['attack_url']}?"
                                parent_url=f"{url['attack_url']}?"
                                for k,_ in url['parameters'].items():  # Looping parameters in each URL
                                    self.parameter_list.append({url['attack_url']:k})
                                    for data in p[1]:  # Looping each payload in a each vulerability
                                        for capec_id,payload in data.items():  # ignore just accessing the dict
                                            if len(url['parameters'])==1:
                                                attack_map['url'].append({capec_id:f"{parent_url}{k}={payload}"})
                                                attack_map['attack_parameter']=k
                                                attack_map['attack_payload']=payload
                                            elif len(url['parameters'])>1:
                                                param=str()
                                                for k1,v1 in url[
                                                    'parameters'].items():  # Create query string for fuzzy parameters
                                                    if k1!=k:
                                                        # param = f"&{param}{k1}={v1}&"
                                                        param=f"{param}{k1}={v1}&"
                                                attack_map['url'].append(
                                                    {capec_id:f"{parent_url}{k}={payload}&{param}"[:-1]})
                                                attack_map['attack_parameter']=k
                                                attack_map['attack_payload']=payload

                                if not self.attacker(request=attack_map):
                                    return False

                            elif url['requestType'].upper()=='POST' and url['parameters']:
                                parent_url=f"{url['attack_url']}"
                                ###MEM_TEST###
                                # attack_map = dict()
                                attack_map={}
                                ###############
                                attack_map['session']=http_session
                                attack_map['method']=url['requestType'].upper()
                                # attack_map['url'] = f"{self.auth_details['authentication']['homepage_url']}{url['attack_url']}"
                                attack_map['url']=parent_url
                                attack_map['url_id']=url['url_id']
                                attack_map['payload']=list()
                                attack_map['vulnerability']=p[0]
                                attack_map['service']=service_name

                                for k,_ in url['parameters'].items():
                                    for data in p[1]:
                                        for capec_id,payload in data.items():
                                            if len(url['parameters'])==1:
                                                attack_map['payload'].append({capec_id:{k:payload}})
                                                attack_map['attack_parameter']=k
                                                attack_map['attack_payload']=payload
                                            elif len(url['parameters'])>1:
                                                param=dict()
                                                for k1,v1 in url['parameters'].items():
                                                    if k1!=k:
                                                        param[k1]=v1
                                                    else:
                                                        param[k]=payload
                                                attack_map['payload'].append({capec_id:param})
                                                attack_map['attack_parameter']=k
                                                attack_map['attack_payload']=payload
                                if not self.attacker(request=attack_map):
                                    return False
                        except Exception as err:
                            self.log.critical(f"Attack: Exception raised when generating URL list for attack: {err}")
                            traceback.print_stack(err)
                            return False
            except Exception as err:
                self.log.critical(f"Attack: Exception raised when generating URL list for attack: {err}")
                traceback.print_stack()
                return False
        return True

    def attacker(self,**kwargs):
        http_request=kwargs.get('request')
        cache_channel=self.redis.connect(host=was.was['cache'])
        attack_completed=True
        try:
            ###MEM_TEST###
            # header, http_snippet = dict(), list()
            header,http_snippet={},[]
            ############
            if http_request['method']=='GET':
                self.log.info(f"Firing URLs {http_request['url']} with vulnerability {http_request['vulnerability']}")

                for url in http_request['url']:
                    try:
                        for capec_id,furl in url.items():
                            try:
                                #if self.cms.check_cms_value(application_id=self.application_id, app_name=self.app_name):
                                self.count+=1
                                self.log.info(f"Generating WAS header for {furl} | request{self.count}")
                                header[
                                    'virsec-uid']=f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}#{self.generate_uuid()}"
                                http_request['url']=furl
                                http_request['header']=header
                                http_request['cookie']=None
                                http_request['verify']=False
                                response=self.perform_request(http_request)
                                if response==None:
                                    self.error_urls.append(f"{http_request['url']} REASON: {self.request_exception_reason}")

                                elif response.status_code in was.configuration["report"]["error_codes"]:
                                    self.error_urls.append(f"{http_request['url']} CODE: {response.status_code}")
                                    response=self.perform_request(http_request)

                                if response!=None and response.status_code in was.configuration["report"][
                                    "inclusion_status_codes"]:
                                    self.attack_progress()
                                    cache_map=dict()
                                    cache_map['request_id']=f"request{self.count}"
                                    cache_map['uid']=header['virsec-uid']
                                    cache_map['method']=http_request['method']
                                    cache_map['url']=furl
                                    cache_map['vulnerability']=http_request['vulnerability']
                                    cache_map['service']=http_request['service']
                                    cache_map['response']=response.status_code  # 'test'  #chg
                                    # cache_map['response_content'] = compress(bytes("\\n".join(str(response.content).split("\\n")[0:2]),encoding='utf8'))
                                    cache_map['response_content']=str(response.content)[0:50]
                                    cache_map['attack_parameter']=http_request['attack_parameter']
                                    cache_map['attack_payload']=http_request['attack_payload']
                                    # with open("./fired_urls.txt",'a') as f:
                                    #     f.write(f"###########URL Attack##############\n")
                                    #     f.write(f"URL: {str(cache_map['url'])}\n")
                                    #     f.write(f"Payload: {http_request['payload']}\n")
                                    #     f.write(f"method: {http_request['method']}\n")
                                    #     f.write(f"header: {str(header)}\n")
                                    #     f.write(f"response: {str(response.status_code)}\n")
                                    cache_channel.hset(self.application_id,f"request{self.count}",str(cache_map))
                                    cache_channel.hset(self.application_id,f"request{self.count}_payload",
                                        str(http_request['payload']))
                                # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                                # time.sleep(1)
                                # else:
                                #     attack_completed = False
                                #     self.Update_Attack_status(
                                #         redis_update="report_generation",
                                #         attack_state='report_generation',
                                #         detail_state='aborted',
                                #         message="Attack aborting as App status in CMS was not in 'NORMAL'/'THREAT'/'ATTACK'",
                                #         subject=f"Attack aborted for App: {self.app_name}"
                                #     )
                                #     return False
                            except Exception as err:
                                self.log.critical(f"Attack: Exception raised when performing attack: {err}")
                                traceback.print_stack(err)
                                attack_completed=False
                                return False

                    except Exception as err:
                        self.log.critical(f"Attack: Exception raised when performing attack: {err}")
                        traceback.print_stack(err)
                        attack_completed=False
                        return False

            elif http_request['method']=='POST':
                self.log.info(
                    f"Firing payload POST {http_request['payload']} from {http_request['vulnerability']} to URL {http_request['url']}")
                try:
                    for payload in http_request['payload']:
                        try:
                            for capec_id,data in payload.items():
                                #if self.cms.check_cms_value(application_id=self.application_id, app_name=self.app_name):
                                self.count+=1
                                self.log.info(
                                    f"Generating WAS header for url {http_request['url']} | request{self.count}")
                                header[
                                    'virsec-uid']=f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}#{self.generate_uuid()}"

                                http_request['payload']=data
                                http_request['header']=header
                                http_request['cookie']=None
                                http_request['verify']=False
                                response=self.perform_request(http_request)
                                if response==None:
                                    self.error_urls.append(f"{http_request['url']} REASON: {self.request_exception_reason}")

                                elif response.status_code in was.configuration["report"]["error_codes"]:
                                    self.error_urls.append(f"{http_request['url']} CODE: {response.status_code}")
                                    response=self.perform_request(http_request)

                                if response!=None and response.status_code in was.configuration["report"][
                                    "inclusion_status_codes"]:
                                    self.attack_progress()
                                    cache_map=dict()
                                    cache_map['request_id']=f"request{self.count}"
                                    cache_map['uid']=header['virsec-uid']
                                    cache_map['method']=http_request['method']
                                    cache_map['url']=http_request['url']
                                    cache_map['vulnerability']=http_request['vulnerability']
                                    cache_map['service']=http_request['service']
                                    cache_map['response']=response.status_code  # chg
                                    #cache_map['response_content'] = compress(bytes("\\n".join(str(response.content).split("\\n")[0:2]),encoding='utf8'))
                                    cache_map['response_content']=str(response.content)[0:50]
                                    cache_map['attack_parameter']=http_request['attack_parameter']
                                    cache_map['attack_payload']=http_request['attack_payload']
                                    cache_channel.hset(self.application_id,f"request{self.count}",str(cache_map))
                                    cache_channel.hset(self.application_id,f"request{self.count}_payload",
                                        str(data))
                                    # with open("./fired_urls.txt",'a') as f:
                                    #     f.write(f"###########URL Attack##############\n")
                                    #     f.write(f"URL: {str(cache_map['url'])}\n")
                                    #     f.write(f"Payload: {data}\n")
                                    #     f.write(f"method: {http_request['method']}\n")
                                    #     f.write(f"header: {str(header)}\n")
                                    #     f.write(f"response: {str(response.status_code)}\n")
                                # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                                # time.sleep(1)
                                # else:
                                #     attack_completed = False
                                #     self.Update_Attack_status(
                                #         redis_update="report_generation",
                                #         attack_state='report_generation',
                                #         detail_state='aborted',
                                #         message="Attack aborting as App status in CMS was not in 'NORMAL'/'THREAT'/'ATTACK'",
                                #         subject=f"Attack aborted for App: {self.app_name}"
                                #     )
                                #     return False
                        except Exception as err:
                            self.log.critical(f"Attack: Exception raised when performing attack: {err}")
                            traceback.print_stack(err)
                            attack_completed=False
                            return False

                except Exception as err:
                    self.log.critical(f"Attack: Exception raised when performing attack: {err}")
                    traceback.print_stack(err)
                    attack_completed=False
                    return False

        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)
            attack_completed=False
            return False

        finally:
            if attack_completed:
                self.log.info(
                    f"Attack completed : on  Payload Combination {http_request['vulnerability']} and URL {http_request['url']}")
                return True
            else:
                self.log.error(
                    f"Attack Terminated : on  Payload Combination {http_request['vulnerability']} and URL {http_request['url']}")

    def app_Validation(self):
        cache_channel=self.redis.connect(host=was.was['cache'])
        for self.attack_user,attack_user_data in self.attack_users['attack']['users'].items():  # Looping all users.
            try:
                # changed
                self.users_login_calls=self.app_auth_details["users"]
                if self.attack_user in self.users_login_calls:
                    self.log.info("Application Auth Validation Initiated for user: ",self.attack_user)
                    app_user_validation="failure"

                    for login_call in self.users_login_calls[self.attack_user]["http_stream"]:  # loop thru all calls
                        if login_call["method"]=="POST" and "requestBody" in login_call:
                            app_session=requests.Session()
                            response=app_session.post(url=login_call['url'],data=login_call['requestBody'])
                            if response.status_code==200:
                                app_user_validation="success"
                                app_session.close()
                            else:
                                app_session.close()
                    if app_user_validation=="success":
                        self.log.info(f"Application Validation Success for User {self.attack_user}")
                    else:
                        self.log.info(f"Application Validation Failed for User {self.attack_user}")
                        self.log.info(f"Application Validation Failed for Application {self.application_id}")

                        self.log.critical(f"Aborting attack operation! Failed to Validate App. Authentication")
                        self.Update_Attack_status(
                            redis_update="report_generation",
                            attack_state='report_generation',
                            detail_state='aborted',
                            message=f"Attack operation partially completed for application {self.app_name}, Application Validation Failed.",
                        )

                        return 'failure'
            except Exception as err:
                self.log.error(err)
                traceback.print_stack(err)
                self.log.critical(f"Aborting attack operation! Failed to Validate App. Authentication")
                self.Update_Attack_status(
                    redis_update="report_generation",
                    attack_state='report_generation',
                    detail_state='aborted',
                    message=f"Attack operation partially completed for application {self.app_name}. Application Validation Failed.",
                )
                return 'failure'

        self.log.info(f"Application Validation Success for Application {self.application_id}")
        return 'success'

    def Update_Attack_status(self,redis_update="",attack_state="",detail_state="",message="",subject="",
                             operation="",max_count=0):
        end_time=time.time()
        # cache_channel = self.redis.connect(host=was.was['cache'])
        # cache_channel.hset(self.application_id, 'attack_state', attack_state)#'aborted: services_not_found')
        cache_update=""
        if detail_state=="aborted":
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':"report_generation",
                'attack.attack_partially_completed':end_time}},
                {'application_id':self.application_id},upsert=True)
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':'report_generation'}},
                {'application_id':self.application_id},upsert=True)
            cache_update="aborted"

            if max_count>2:
                self.log.info(f"Generating report")
                #self.report_for_exception(message)
                self.reporting(message,end_time)
                redis_update='completed'
                self.mongo.update_document(self.app_store,{'$set':{'detail.state':'report_ready'}},
                    {'application_id':self.application_id},upsert=True)
                self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':'completed'}},
                    {'application_id':self.application_id},upsert=True)
            else:
                status=self.investigate()
                if status=='investigation_success':
                    self.log.info(f"Generating report")
                    self.reporting(message,end_time)
                    redis_update='completed'
                    self.mongo.update_document(self.app_store,{'$set':{'detail.state':'report_ready'}},
                        {'application_id':self.application_id},upsert=True)
                    self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':'completed'}},
                        {'application_id':self.application_id},upsert=True)

            #self.set_cms_to_attack_done()

        elif detail_state=="attack_completed":
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':attack_state,
                'attack.attack_completed':end_time}},
                {'application_id':self.application_id},upsert=True)
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':detail_state}},
                {'application_id':self.application_id},upsert=True)
            cache_update="completed"
            self.set_cms_to_attack_done()

        elif detail_state=="report_ready":
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':attack_state,
                'attack.attack_completed':end_time}},
                {'application_id':self.application_id},upsert=True)
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':detail_state}},
                {'application_id':self.application_id},upsert=True)

            cache_update="report_ready"
            self.set_cms_to_attack_done()

        elif detail_state=="report_aborted":
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':'report_generation'}},
                {'application_id':self.application_id},upsert=True)
            cache_update="aborted"
            self.log.info(f"Generating report")
            self.report_for_exception(message,end_time)
            redis_update='completed'
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':'report_ready'}},
                {'application_id':self.application_id},upsert=True)
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':'completed',
                'attack.attack_completed':end_time}},
                {'application_id':self.application_id},upsert=True)
            #self.set_cms_to_attack_done()

        elif detail_state=="report_generation":
            self.mongo.update_document(self.app_store,{'$set':{'detail.state':detail_state}},
                {'application_id':self.application_id},upsert=True)
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':attack_state}},
                {'application_id':self.application_id},upsert=True)
            cache_update="report_generation"

        elif detail_state=="attacking":
            self.mongo.update_document(self.app_store,{'$set':{'attack.attack_state':attack_state}},
                {'application_id':self.application_id},upsert=True)

            self.mongo.update_document(self.app_store,{'$set':{'detail.state':detail_state}},
                {'application_id':self.application_id},upsert=True)
        else:
            self.log.info("Unexpected Scenario Found.")
            # cache_update=False
        self.update_cache(state_key="attack",cache_update=redis_update)
        #self.update_cache(state_key="attack", cache_update=redis_update)
        #here add report message
        if message!="":
            util.Notification().send_notification(message=message,
                application_id=self.application_id,
                operation=operation,
                application_name=self.app_name,
                subject=subject
            )

    def parse_log(self,log_path):
        # Add UUID values to a list
        try:
            with open(log_path,'r') as f:
                line_nums=[]
                search_phrase1="ActiveMQ_Mgr::send: JSON: (MsgSeq#"
                search_phrase2="Dest: DBI-CMS-QUEUE): {"  # "Dest: SW-EXC-LOG-QUEUE"

                line_num=0
                for line in f.readlines():
                    line_num+=1
                    if (line.find(search_phrase1)>=0) and line.find(search_phrase2)>=0:
                        line_nums.append(line_num)  # print line_num

            f=open(log_path,'r')
            line_data=f.readlines()
            uuids=[]
            tables=[]
            threatscores=[]
            levels=[]
            threat_descs=[]
            RequestIds=[]
            virsec_uids=[]
            user_ids=[]
            timestamp=[]
            self.comvirsec_request=[]
            for index,line in enumerate(line_nums):
                temp_uuid=None
                temp_virsecuid=""
                # Iterate to the next line until i find uuid
                for loopline in range(1+line,1+line+30):
                    linevalue=(line_data[loopline])

                    if "ActiveMQ_Mgr::send: JSON: (MsgSeq" in linevalue:
                        break
                    if linevalue.strip()=="}":
                        break

                    if '"Table" :' in linevalue or '"Table":' in linevalue:
                        temp=(linevalue.strip(",").strip().split(":"))[1]
                        temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        tables.append(temp)

                    if '"threatscore" :' in linevalue or '"threatscore":' in linevalue:
                        temp=(linevalue.strip(",").strip().split(":"))[1]
                        temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        threatscores.append(temp)  # ((linevalue.strip(",").strip().split(":"))[1])

                    if '"uuid" :' in linevalue or '"uuid":' in linevalue:
                        temp_uuid=(linevalue.strip(",").strip().split(":"))[1]
                        temp_uuid=temp_uuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        if temp_uuid.count('-')==2:
                            uuids.append(temp_uuid)

                    if '"level" :' in linevalue or '"level":' in linevalue:
                        temp=(linevalue.strip(",").strip().split(":"))[1]
                        temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        levels.append(temp)

                    if '"threat_desc" :' in linevalue or '"threat_desc":' in linevalue:
                        temp=(linevalue.strip(",").strip().split(":"))[1]
                        temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        threat_descs.append(temp)

                    if '"RequestId" :' in linevalue or '"RequestId":' in linevalue:
                        req=(linevalue.strip(",").strip().split(":"))[1]
                        req=req.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        RequestIds.append(req)

                    if '"virsec-uid" :' in linevalue or '"virsec-uid":' in linevalue:
                        temp_virsecuid=(linevalue.strip(",").strip().split(":"))[1]
                        temp_virsecuid=temp_virsecuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        # virsec_uids.append(temp_virsecuid)

                    if '"user_id" :' in linevalue or '"user_id":' in linevalue:
                        temp_userid=":".join((linevalue.strip(",").strip().split(":"))[1:])
                        temp_userid=temp_userid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        user_ids.append(temp_userid)

                    if '"ts" :' in linevalue or '"ts":' in linevalue:
                        temp_timestamp=":".join((linevalue.strip(",").strip().split(":"))[1:])
                        temp_timestamp=temp_timestamp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                        if "T" in temp_timestamp:
                            timestamp.append(temp_timestamp)

                virsec_uids.append(temp_virsecuid)
                unique_id=temp_virsecuid+"_"+str(req)
                self.comvirsec_request.append(unique_id)
            f.close()
            log_map={}
            # self.uuids= uuids
            # combined virsec_id,
            # temp = len(temp_virsecuid) * '% s _ %% s, '
            # self.comvirsec_request = temp % tuple(temp_virsecuid) % tuple(RequestIds)
            for num,value in enumerate(self.comvirsec_request):
                if virsec_uids[num]!="":
                    request_num=int((virsec_uids[num].split('#')[5]).replace("request",""))
                    if request_num>0:
                        # self.log.info(f"Adding request Number {request_num} due to Initial count Initial_Request_Count {self.Initial_Request_Count}")
                        log_map[value]={"level":levels[num],
                            "table":tables[num],
                            "threatscore":threatscores[num],
                            "threat_desc":threat_descs[num],
                            "RequestId":request_num,  # virsec_uids[num].split('#')[5], #RequestIds[num],
                            "uuid":uuids[num],
                            "user_id":user_ids[num],
                            "virsec_uid":virsec_uids[num],
                            "ts":timestamp[num]}

                    # else:
                    #     self.log.info(f"Ignoring request Number {request_num} due to Initial count Initial_Request_Count {self.Initial_Request_Count}")
            self.log.info(f"Found {len(log_map)} UUID values in Log")
            self.uuids=list(log_map.keys())
            # self.uuids = list(map(lambda key: log_map[key]['uuid'], log_map.keys()))

            #
            return log_map
        except Exception as err:
            self.log.critical(f"Attack: Exception raised when parsing AE log: {err}")

    def investigate(self):
        error_message=None
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            access_token=self.cms.token_status()
            cms_services_header=util.Authentication().create_http_header('services',access_token,
                cms['ipv4_address'])

            application_ae=self.cms.application_analysis_engine(self.application_id,cms_services_header)
            application_ae_address=application_ae[0]['serverNetworkInfo']['ipAddress']
                        
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_generation',
                message=f"Report generation operation started for application {self.app_name}",
                subject=f"Report generation started for App: {self.app_name}",
                operation="Report"
            )
            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='report_generation')
            # self.Update_Attack_status(attack_state='report_generation', detail_state='report_generation')
            # message = f"Report generation operation started for application {self.app_name} ({self.application_id})"
            # util.Notification().send_notification(message=message,
            #                                         application_id=self.application_id,
            #                                         operation='Report',
            #                                         application_name=self.app_name)
            self.log.info(f"Attack completed; Started investigating")
            if application_ae_address:
                
                if "nt" in os.name:
                    local_dir=f"C:/emejson.log"  # f"/tmp/artefacts/traces/ae/{self.application_id}.log"
                else:
                    local_dir=f"/tmp/emejson.log"  # f"/tmp/artefacts/traces/ae/{self.application_id}.log"

                #cms_username="virsec"
                # cms_password= "P@ssword1"
                # establish ssh connection between your local machine and the jump server
                if not self.cms.generate_cms_vm_login_info():
                    error_message="Report generation Aborted; CMS VM configaration not found"
                    raise Exception
                if not self.cms.generate_ae_vm_login_info(cms_ip=cms['ipv4_address'],application_ae_address=application_ae_address):
                    error_message="Report generation Aborted; AE VM configaration not found"
                    raise Exception
                cms_session=SSHSession(
                    cms['ipv4_address'],
                    username=self.cms.cms_vm_username,
                    password=self.cms.cms_vm_password,
                    look_for_keys=False,
                    allow_agent=False
                ).open()
                ae_session=cms_session.get_remote_session(
                    application_ae_address,
                    username=self.cms.ae_vm_username,
                    password=self.cms.ae_vm_password,
                    look_for_keys=False,
                    allow_agent=False
                )
                ae_session.get(self.cms.ae_log_path,local_dir,use_sudo=False)
                ae_session.close()
                cms_session.close()

                os.stat(local_dir)
                if os.path.exists(local_dir):
                    log_map=self.parse_log(local_dir)
                    # log_map= self.parse_log_new(local_dir)
                    # cms_incidents = fw.CMS(cms['ipv4_address']).application_incidents(self.application_id,
                    #     cms_services_header)
                    ##### CMS_TOKEN##########
                    # if self.check_cms_value():
                    #     cms_incidents = fw.CMS(cms['ipv4_address']).application_incidents_all(self.application_id,
                    #                                                                       cms_services_header,
                    #                                                                       return_empty_response=True)
                    # else:
                    #     cms_incidents = fw.CMS(cms['ipv4_address']).application_details_from_archived(self,cms_services_header,self.application_id)

                    self.report_start_time=int(datetime.now(tz=timezone.utc).timestamp()*1000)
                    cms_incidents=self.fetch_incidents(cms_services_header)
                    if cms_incidents=="cms_token_expired":
                        self.log.warning(f"Regenerating token to connect to CMS")
                        status=self.cms.refresh_token(cms['username'])
                        self.max_count+=1
                        if status=='success':
                            self.log.info(
                                f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                            # user = util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                            access_token=self.cms.token_status()
                            cms_services_header=util.Authentication().create_http_header('services',access_token,
                                cms['ipv4_address'])
                            # cms_incidents = fw.CMS(cms['ipv4_address']).application_incidents_all(self.application_id,
                            #                                                           cms_services_header,
                            #                                                           return_empty_response=True)
                            cms_incidents=self.fetch_incidents(cms_services_header)
                        elif 'error' in status:
                            self.Update_Attack_status(
                                redis_update="report_generation",
                                attack_state='report_generation',
                                detail_state='aborted',
                                message=f"Report generation operation partially completed as for application {self.app_name} as CMS token expired",
                                subject=f"Report generation partially completed for App: {self.app_name}",
                                operation="Report",
                                max_count=self.max_count
                            )
                            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                            # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                            # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id})"
                            # util.Notification().send_notification(message=message,
                            #                                         application_id=self.application_id,
                            #                                         operation='Report',
                            #                                         application_name=self.app_name)
                            if 'captcha' in status['error_description']:
                                return 'cms_captcha_error'
                            else:
                                return 'cms_authentication_error'

                    #TODO: Add condition for validation from fetch incidents
                    if cms_incidents in ['invalid_application',"cms_fetch_error","cms_401",\
                            'connection_error','http_error','base_exception','decode_error',
                        'exception',False]:
                        self.log.error(
                            f"Exiting report generation as fetching all CMS incidents returned: {cms_incidents}")
                        self.Update_Attack_status(
                            redis_update="report_generation",
                            attack_state='report_generation',
                            detail_state='report_aborted',
                            message=f"Report generation operation partially completed for application {self.app_name} as CMS incidents not found ",
                            subject=f"Report operation partially completed for App: {self.app_name}",
                            operation="Report"
                        )
                        # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                        # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                        # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as CMS throwed {cms_incidents}"
                        # util.Notification().send_notification(message=message,
                        #                                         application_id=self.application_id,
                        #                                         operation='Report',
                        #                                         application_name=self.app_name)
                        return cms_incidents
                        # if cms_incidents == "cms_token_expired":
                        #     self.log.error(f"Exiting report generation as token expired after refresing: {cms_incidents}")
                        #     self.Update_Attack_status(
                        #         redis_update="aborted",
                        #         attack_state='aborted',
                        #         detail_state='aborted',
                        #         message=f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as CMS token expired",
                        #         subject=f"Report aborted for App: {self.app_name}",
                        #         operation="Report"
                        #     )
                        # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                        # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                        # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as CMS token expired"
                        # util.Notification().send_notification(message=message,
                        #                                         application_id=self.application_id,
                        #                                         operation='Report',
                        #                                         application_name=self.app_name)
                        return "cms_token_expired"
                    ###################
                    # if isinstance(cms_incidents,list):
                    #     if len(cms_incidents) == 0:
                    #         self.log.error(f"Exiting report generation as no incidents were reported from CMS")
                    #         self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                    #         message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as no incidents were reported from CMS"
                    #         util.Notification().send_notification(message=message,
                    #                                                 application_id=self.application_id,
                    #                                                 operation='Report',
                    #                                                 application_name=self.app_name)
                    #         return "CMS_incidents_empty"

                    cms_incident_ids=list()
                    for incident in cms_incidents:
                        cms_incident_ids.append(incident['id'])

                        # Murali Change: Stale state
                    ###########################
                    # n=util.Network()
                    # ip_addr=n.get_ipv4()
                    ip_addr=was.was["host_ip"]
                    ###########################
                    known_incidents={}
                    for incident in cms_incident_ids:
                        # incident_detail = self.cms.application_incident_detail(self.application_id,
                        #                                                                             cms_services_header, incident,
                        #                                                                             return_empty_response=True)
                        incident_detail=self.fetch_each_incident_detail(cms_services_header,incident)
                        # sleep(1)
                        if incident_detail=="cms_token_expired":
                            self.log.warning(f"Regenerating token to connect to CMS")
                            status=self.cms.refresh_token(cms['username'])
                            self.max_count+=1
                            if status=='success':
                                self.log.info(
                                    f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                                # user = util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                                access_token=self.cms.token_status()
                                cms_services_header=util.Authentication().create_http_header('services',access_token,
                                    cms['ipv4_address'])
                                incident_detail=self.fetch_each_incident_detail(cms_services_header,incident)
                            elif 'error' in status:
                                self.Update_Attack_status(
                                    redis_update="report_generation",
                                    attack_state='report_generation',
                                    detail_state='aborted',
                                    message=f"Report generation operation partially completed as for application {self.app_name} as CMS token expired",
                                    subject=f"Report generation partially completed for App: {self.app_name}",
                                    operation="Report",
                                    max_count=self.max_count
                                )
                                # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                                # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                                # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id})"
                                # util.Notification().send_notification(message=message,
                                #                                         application_id=self.application_id,
                                #                                         operation='Report',
                                #                                         application_name=self.app_name)
                                if 'captcha' in status['error_description']:
                                    return 'cms_captcha_error'
                                else:
                                    return 'cms_authentication_error'

                        if incident_detail in ['invalid_application',"cms_fetch_error","cms_401",\
                                'connection_error','http_error','base_exception','decode_error',
                            'internal_server_error']:
                            self.log.error(
                                f"Exiting report generation as fetching individual CMS incidents returned: {incident_detail}")
                            self.Update_Attack_status(
                                redis_update="report_generation",
                                attack_state='report_generation',
                                detail_state='report_aborted',
                                message=f"Report generation operation partially completed for application {self.app_name} as CMS incidents not found",
                                subject=f"Report operation partially completed for App: {self.app_name}",
                                operation="Report"
                            )
                            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
                            # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
                            # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as CMS throwed {incident_detail}"
                            # util.Notification().send_notification(message=message,
                            #                                         application_id=self.application_id,
                            #                                         operation='Report',
                            #                                         application_name=self.app_name)
                            return incident_detail
                        # if incident_detail == "cms_token_expired":
                        #     self.log.error(
                        #         f"Exiting report generation as token expired after refresing: {incident_detail}")
                        #     self.Update_Attack_status(redis_update="aborted", attack_state='aborted',
                        #                               detail_state='aborted')
                        #     self.redis.set_status_value(cache_channel, 'attack', self.application_id,
                        #                                 attack_state='aborted')
                        #     message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as CMS token expired"
                        #     util.Notification().send_notification(message=message,
                        #                                           application_id=self.application_id,
                        #                                           operation='Report',
                        #                                           application_name=self.app_name)
                        #     return "cms_token_expired"

                        for log_uid in self.uuids:  # , virsec_uid in uid_map.items():

                            if incident_detail.get('details',{}).get('attributes',{}).get('Threat Level',None) in ['ATTACK','THREAT'] and\
                                    incident_detail.get('details',{}).get('attributes',{}).get('UUID',None)==log_map[log_uid]['uuid'] and\
                                    str(ip_addr) in log_map[log_uid]['user_id'] and\
                                    incident_detail.get('details',{}).get('attributes',{}).get('Attacker',None)==log_map[log_uid]['user_id'] and\
                                    log_map[log_uid]['level'] in ['ATTACK','THREAT']:  # Added extra condition because of 'sql..' valuje returned in level
                                # if "-" in log_map[log_uid]['ts']:
                                # log_ts=log_map[log_uid]['ts'].split('.')[0]
                                log_ts=log_map[log_uid]['ts'][::-1].split("-",1)[-1][::-1]
                                log_format_date=datetime.timestamp(datetime.strptime(log_ts,"%Y-%m-%dT%H:%M:%S.%f"))
                                log_timestamp=datetime.fromtimestamp(log_format_date,tz=timezone.utc)
                                if self.attack_instantiate_timestamp<=log_timestamp:
                                    # if incident_detail['details']['properties']['description'].lower() == "reflectedxss" and \
                                    #         incident_detail['details']['attributes']['Threat Level'].upper() == 'THREAT':
                                    #     continue
                                    # else:
                                    incident_map={}

                                    virsec_uid=log_map[log_uid]['virsec_uid']
                                    incident_map[log_uid]={}
                                    incident_map[log_uid]['uid']=log_map[log_uid]['uuid']

                                    incident_map[log_uid]['capec_id']=virsec_uid.split('#')[4]
                                    incident_map[log_uid]['request_id']=virsec_uid.split('#')[5]
                                    incident_map[log_uid]['service']=virsec_uid.split('#')[6]
                                    incident_map[log_uid]['method']=virsec_uid.split('#')[7]

                                    incident_map[log_uid]['uri']=incident_detail['details']['attributes'][
                                        'HTTP Request']  # .split(' ')[1]
                                    incident_map[log_uid]['url_id']=virsec_uid.split('#')[2]
                                    # incident_map[log_uid]['vulnerability'] = virsec_uid.split('#')[3]
                                    incident_map[log_uid]['vulnerability']=log_map[log_uid]['threat_desc']
                                    incident_map[log_uid]['level']=log_map[log_uid]['level']
                                    incident_map[log_uid][
                                        'attacker']=f"{incident_detail['details']['attributes']['Attacker']} == {log_map[log_uid]['user_id']}"
                                    incident_map[log_uid]['parameter_attack']=\
                                        incident_detail['details']['attributes']['Malicious Input']

                                    known_incidents.update(incident_map)
                                    # #Murali Change: Stale state
                                    # ###########################
                                    # with open("./cms_incidents.txt","a") as f:
                                    #     f.write(str(incident_map)+"\n")
                                    # ###########################
                        else:
                            continue

                    cache_channel.hdel(self.application_id,'known_incidents',str(known_incidents))
                    status=cache_channel.hset(self.application_id,'known_incidents',str(known_incidents))
                    if status==1:
                        return 'investigation_success'

                else:  # AE logs not available
                    self.log.critical(f"Analysis Engine logs not available")
                    return 'ae_logs_not_found'
            else:
                self.log.critical("Unable to find analysis engine address")
                return 'analysis_engine_not_available'

        except exception.ConnectionError as err:
            machine=""
            if cms["ipv4_address"] in str(err):
                machine="CMS"
            else:
                machine="AE"
            self.log.error("Report: Exception {err}")
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_aborted',
                message=f"Report generation not completed for application {self.app_name}; unable to login into {machine} with configured username/password",
                subject=f"Report partially completed for App: {self.app_name}",
                operation="Report"
            )
        except exception.SSHException as err:
            self.log.error("Report: Exception {err}")
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_aborted',
                message=f"Report generation not completed for application {self.app_name}; unable to connect to AE machine",
                subject=f"Report partially completed for App: {self.app_name}",
                operation="Report"
            )
            self.log.error(f"Exception; {err}")
        except FileNotFoundError:
             self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_aborted',
                message=f"Report generation not completed for application '{self.app_name}' as emejson file was not found in configured path",
                subject=f"Report partially completed for App: {self.app_name}",
                operation="Report"
            )
        except Exception as err:
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_aborted',
                message=error_message or f"Report generation operation partially completed for application {self.app_name} Exception raised",
                subject=f"Report partially completed for App: {self.app_name}",
                operation="Report"
            )
            self.log.error(f"Exception; {err}")
        finally:
            if "cms_incident_ids" in locals():
                del cms_incident_ids
            if "cms_incidents" in locals():
                del cms_incidents
            if "known_incidents" in locals():
                del known_incidents
            if db_channel:
                db_channel.close()
                
    def message_block(self,message='',ex_time=0):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            exception_message = message
            exception_time = ex_time
            messages={"messages":{
                "msg_summery":'',
                "msg":[] }}
            each_msg = {}
            not_instrumented_list=set()
            instrumented_list = set()
            
            if cache_channel.hexists(self.application_id,'not_instrumented'):
                    time_list=cache_channel.hget(self.application_id,'not_instrumented').decode('utf-8')
                
                    if '#' in str(time_list):
                        s= str(time_list)
                        not_instrumented_list = set(s.split('#'))
                    else:
                        not_instrumented_list.add(time_list)
            each_msg_id = 0
                
            for i in not_instrumented_list:
                key_id = f"message_{each_msg_id}"
                each_msg[key_id]= {}
                each_msg[key_id]['message_id'] = key_id
                each_msg[key_id]['message_details'] = "Application gone to not instrumented "
                each_msg[key_id]['timestamp'] = float(i)
                    
                    
                each_msg_id += 1
                
            if cache_channel.hexists(self.application_id,'instrumented'):
                time_instrumented_list=cache_channel.hget(self.application_id,'instrumented').decode('utf-8')
                
                if '#' in str(time_instrumented_list):
                    s= str(time_instrumented_list)
                    instrumented_list = set(s.split('#'))
                else:
                    instrumented_list.add(time_instrumented_list)
                
            for i in instrumented_list:
                key_id = f"message_{each_msg_id}"
                each_msg[key_id]= {}
                each_msg[key_id]['message_id'] = key_id
                each_msg[key_id]['message_details'] = "Application gone to instrumented"
                each_msg[key_id]['timestamp'] = float(i)
                    
                    
                each_msg_id += 1
            if len(exception_message) != 0:
                exception_msg_id = f"message_{each_msg_id}"
                each_msg[exception_msg_id] = {}
                each_msg[exception_msg_id]['message_id'] = exception_msg_id
                each_msg[exception_msg_id]['message_details'] = exception_message
                each_msg[exception_msg_id]['timestamp'] = float(exception_time)
            else:
                if len(each_msg) != 0:
                    partial_msg = "Report is partially completed due to application status changed"
                    partial_msg_id = f"message_{each_msg_id}"
                    each_msg[partial_msg_id] = {}
                    each_msg[partial_msg_id]['message_id'] = partial_msg_id
                    each_msg[partial_msg_id]['message_details'] = partial_msg
                    each_msg[partial_msg_id]['timestamp'] = time.time()
            
            each_msg = sorted(each_msg.values(),key=lambda i:i['timestamp'],reverse=True)
            
            for val in each_msg:
                messages['messages']['msg'].append(val)
                
            messages['messages']['msg_summery'] = f"Application gone in not instrumentation {len(not_instrumented_list)} times and instrumented {len(instrumented_list)} times."  
            
            return  messages 
        except Exception as e:
            self.log.error(f"Exception occured in the message block {e}")
            
        finally:
            cache_channel.hdel(self.application_id,'not_instrumented')
            cache_channel.hdel(self.application_id,'instrumented')
            
    
    def reporting(self,message='',ex_time=0):
        try:
            #capture_noninstrumented_time
            vun={
                "CAPEC-A1-CMDi":"CMDi",
                "CAPEC-A1-SQLi":"SQLi",
                "CAPEC-A7-StoredXSS":"StoredXSS",
                "CAPEC-A7-ReflectiveXSS":"ReflectedXSS",
                "CAPEC-A5-RFI":"RFi",
                "CAPEC-A5-PathTraversal":"PathTraversal"
            }

            owasp_distrubution={
                "CAPEC-A1-SQLi":{"owasp_description":"2017-Injection",
                    "owasp_id":"A1"},
                "CAPEC-A7-ReflectiveXSS":{"owasp_description":"2017-ReflectedXSS",
                    "owasp_id":"A7"},
                "CAPEC-A1-CMDi":{"owasp_description":"2017-Injection",
                    "owasp_id":"A1"},
                "CAPEC-A5-RFI":{"owasp_description":"2017-Injection",
                    "owasp_id":"A5"},
                "CAPEC-A7-StoredXSS":{"owasp_description":"2017-Cross-Site Scripting XSS",
                    "owasp_id":"A7"},
                "CAPEC-A5-PathTraversal":{"owasp_description":"2017-Broken Access Control",
                    "owasp_id":"A5"}

            }
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
          
            db=self.mongo.create_database(db_channel,'was_db')
            # Murali Change: Stale state
            ###########################
            self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='report_generation')
            self.Update_Attack_status(redis_update="report_generation",attack_state='report_generation',
                detail_state='report_generation')
            ###########################

            app_store=self.mongo.create_collection(db,'applications')
            app_data=self.mongo.find_document(app_store,{'application_id':self.application_id})
            # self.payload_store = self.mongo.create_collection(db, 'payload_store')
            data=self.mongo.find_all_documents(self.payload_store)
            self.payloads=[]
            for i in data:
                i.pop('_id')
                self.payloads.append(i)

            # payload_capec_id=list(set([data['capec_id'] for i in payloads for k,v in i.items() for data in v]))
            url_store_coll=self.mongo.create_collection(db,'url_store')
            url_store=self.mongo.find_document(url_store_coll,{'application_id':self.application_id})
            known_incidents=util.ConvertData(
                cache_channel.hget(self.application_id,'known_incidents').decode('utf-8')).framework_compatible()

            # if(len(known_incidents) != 0):

            all_vulnerabilities={}
            req_id=0
            for incident_uid,incident_details in known_incidents.items():
                # if incident_details['capec_id'] in payload_capec_id:
                request_details=cache_channel.hget(self.application_id,incident_details['request_id'])
                # request_details = util.ConvertData(
                #     cache_channel.hget(self.application_id, incident_details['request_id']).decode(
                #         'utf-8')).framework_compatible()
                request_payload=cache_channel.hget(self.application_id,f"{incident_details['request_id']}_payload")
                if request_payload!=None and request_details!=None:
                    request_details=util.ConvertData(request_details.decode('utf-8')).framework_compatible()
                    request_payload=request_payload.decode('utf-8')
                    if incident_details['vulnerability'].lower()=='reflectedxss' and incident_details[
                        'level'].upper()=='THREAT':
                        continue
                    else:
                        if (incident_details['vulnerability'].lower()==vun.get(request_details['vulnerability'],
                                "not_found").lower()):
                            vulnerabilities={}
                            request_data="request"+str(req_id)
                            vulnerabilities[request_data]={}
                            vulnerabilities[request_data]['request_id']=request_details['request_id']
                            vulnerabilities[request_data]['uid']=request_details['uid']
                            vulnerabilities[request_data]['method']=request_details['method']
                            # vulnerabilities[request_details['request_id']]['url'] = {'url':request_details['url'].split("?")[0]}
                            vulnerabilities[request_data]['url']=request_details['url']

                            # vulnerabilities[request_details['request_id']]['url'] = request_details['url']
                            vulnerabilities[request_data]['payload']=request_payload
                            vulnerabilities[request_data]['response']=request_details['response']
                            vulnerabilities[request_data]['vulnerability']=request_details['vulnerability']
                            vulnerabilities[request_data]['url_id']=incident_details['url_id']
                            vulnerabilities[request_data]['capec_id']=incident_details['capec_id']
                            # vulnerabilities[request_details['request_id']]['capec_id'] = incident_details['capec_id']
                            vulnerabilities[request_data]['service']=incident_details['service']
                            vulnerabilities[request_data]['level']=incident_details['level']
                            vulnerabilities[request_data]['http_response_code']=request_details['response']
                            # vulnerabilities[request_details['request_id']]['http_response']=str(decompress(request_details['response_content']))
                            vulnerabilities[request_data]['http_response']=request_details['response_content']
                            if 'header_parameter' in request_details.keys():
                                vulnerabilities[request_data]['header_parameter']=request_details['header_parameter']
                            # vulnerabilities[request_details['request_id']]['attack_parameter']=request_details['attack_parameter']
                            vulnerabilities[request_data]['attack_parameter']=incident_details['parameter_attack']
                            # vulnerabilities[request_details['request_id']]['attack_payload']=request_details['attack_payload']
                            all_vulnerabilities.update(vulnerabilities)
                            req_id+=1

            report={}
            count=0
            error_urls_dict={}
            self.cwe_dict={}
            error_display=[]
            report['messages']={"msg":[]}
            report['report_id']=util.Authentication().generate_uuid('uuid4')
            report['report_name']=f"{app_data['detail']['name']}_{app_data['detail']['version']}"
            report['report_version']="1.0.0"

            report['application_id']=self.application_id
            report['application_details']={}
            report['application_details']['application_id']=self.application_id
            report['application_details']['application_name']=app_data['detail']['name']
            report['application_details']['application_version']=app_data['detail']['version']
            report['application_details']['application_url']=url_store['authentication']['homepage_url']
            report['application_details']['application_user']=''
            report['application_details']['scan_start_time']=app_data['attack']['attack_instantiated']
            report['application_details']['scan_end_time']=time.time()
            report['application_details']['scan_datetime']=time.time()  # app_data['attack']['attack_completed']
            try:
                #if len(message) != 0:
                output_message = self.message_block(message,ex_time)
                report['messages']= output_message['messages']
                
                     
                if len(report['messages']['msg']) == 0:
                    message = f"Report successfully generated for application {app_data['detail']['name']}"
                    ex_time = time.time()
                    output_message = self.message_block(message,ex_time)
                    report['messages']= output_message['messages']
                
                
                    # message = f"Report partially generated for application {app_data['detail']['name']} because application went unprovisioned"
                    # ex_time = time.time()
                    # output_message = self.message_block(message,ex_time)
                    # report['messages']= output_message['messages']
                    
            except Exception as e:
                self.log.error(f"Exception raised as {e}")
                
                report['messages']['msg'] = []
                report['messages']['msg'].append({'message_id':'message_0',
                                      'message_details':'Exception Raised While Creating Reports.',
                                      'timestamp':float(time.time())})
                report['messages']['msg_summery'] = message
                
            count_i=0
            unique_error_urls=set(self.error_urls)
            for m in unique_error_urls:
                id_url='url_'+str(count_i)
                error_urls_dict[id_url]={}
                error_urls_dict[id_url]['error_id']=id_url
                error_urls_dict[id_url]['error_url']=m
                count_i+=1

            for n in error_urls_dict.values():
                error_display.append(n)

            report['error_containg_urls']=error_display
            if self.current_attack_user=="user_0":
                self.current_attack_user="anonymous"

            report['application_details']['user_credentials_used']= self.current_attack_user
            report['application_details']['application_user']= self.current_attack_user
            if cache_channel.exists('current_user'):
                scan_user=cache_channel.hget('current_user','username').decode('utf-8')

            report['application_details']['scan_profile']=scan_user
            report['application_details']['was_instance']=was.was["host_ip"]
            report['vulnerability_distribution']={}
            report['vulnerability_distribution']['severity']={}

            report['vulnerability_distribution']['severity']["critical"]=0
            report['vulnerability_distribution']['severity']["high"]=0
            report['vulnerability_distribution']['severity']["medium"]=0
            report['vulnerability_distribution']['severity']["low"]=0
            report['vulnerability_distribution']['severity']["info"]=0
            report['vulnerability_distribution']['total_alerts']=0
            # info_required
            crawled=0
            for i,j in url_store['urls'][self.attack_user].items(): crawled+=len(j)
            report['vulnerability_distribution']['urls_crawled']=crawled

            # report['vulnerability_distribution']['urls_crawled'] = len(url_store['urls']['homepage_url'])

            report['services']={}
            capec_discription={}
            capec_id={}

            # f=open("./report_test.txt","a")
            url_no=0
            for rid,rdetails in all_vulnerabilities.items():
                # f.write(f"{rdetails['vulnerability']} having level {rdetails['level']}\n")
                # If this is new service. Add a service
                severity,score=self.generate_cvss_severity(rdetails['vulnerability'].lower(),rdetails['level'])
                url_id="url_"+str(url_no)
                vulnerability_key=rdetails['vulnerability']+"_"+severity.lower()

                if rdetails['service'] not in report['services']:
                    report['services'][rdetails['service']]={}
                    report['services'][rdetails['service']]['service_id']=[rdetails['service']]
                    report['services'][rdetails['service']]['service_url']=url_store['authentication']['homepage_url']
                    report['services'][rdetails['service']]['vulnerabilities']={}

                # If this is new vulnerability, Add a vulnerability
                if vulnerability_key not in report['services'][rdetails['service']]['vulnerabilities']:
                    vuls=report['services'][rdetails['service']]['vulnerabilities']  # {}
                    vuls[vulnerability_key]={}
                    vuls[vulnerability_key]['vulnerability_classification']={}
                    # vuls[rdetails['vulnerability']]['recommendations'] = payloads[rdetails['vulnerability']][0]['solution']
                    # vuls[rdetails['vulnerability']]['references'] = payloads[rdetails['vulnerability']][0]['reference']
                    vuls[vulnerability_key]['risk_factor']=''
                    vuls[vulnerability_key]['urls']={}
                    # vuls[rdetails['vulnerability']]['vulnerability_description'] = payloads[rdetails['vulnerability']][0]['payload_info']
                    vuls[vulnerability_key]['vulnerability_summary']={}
                    for i in self.payloads:
                        for k,v in i.items():
                            if k==rdetails['vulnerability']:
                                vuls[vulnerability_key]['recommendations']=v[0]['solution']
                                vuls[vulnerability_key]['references']=v[0]['reference']
                                vuls[vulnerability_key]['vulnerability_description']=v[0]['payload_info']
                                vuls[vulnerability_key]['vulnerability_summary']['payload_description']=v[0][
                                    'payload_info']
                                vuls[vulnerability_key]['vulnerability_summary']['payload_id']=v[0]['payload_id']
                                decode_data=base64.b64decode(v[0]['payload_data'])
                                vuls[vulnerability_key]['vulnerability_summary'][
                                    'payload_injected']=decode_data.decode("ascii")
                                vuls[vulnerability_key]['vulnerability_summary'][
                                    'payload_type']=self.payload_policy.lower()
                                capec_discription[v[0]['capec_id']]=v[0]['capec_description']
                                capec_id[v[0]['capec_id']]=v[0]['capec_id']
                                # capec_discription = v[0]['capec_description']
                                # f.write(f"{capec_discription} for {k}\n")

                    vuls[vulnerability_key]['vulnerabilility_id']=rdetails['vulnerability']
                    vuls[vulnerability_key]['vulnerability_name']=rdetails['vulnerability']
                    vuls[vulnerability_key]['affected_items']=0
                    vuls[vulnerability_key]['vulnerability_classification']['capec']={}
                    vuls[vulnerability_key]['vulnerability_classification']['cwe']={}
                    vuls[vulnerability_key]['vulnerability_classification']['owasp']={}
                    vuls[vulnerability_key]['vulnerability_classification']['sans']={}
                    vuls[vulnerability_key]['vulnerability_classification']['cvss']={}

                    report['services'][rdetails['service']]['vulnerabilities']=vuls  # {}
                if rdetails['vulnerability'] not in self.cwe_dict.keys():
                    self.cwe_dict[rdetails['vulnerability']]=0

                report['services'][rdetails['service']]['vulnerabilities'][vulnerability_key][
                    'affected_items']+=1  # len(temp)
                # severity,score = self.generate_cvss_severity(rdetails['vulnerability'].lower(), rdetails['level'])
                report['vulnerability_distribution']['severity'][severity.lower()]+=1

                Present_vulnerability=report['services'][rdetails['service']]['vulnerabilities']
                Present_vulnerability[vulnerability_key]['urls'][url_id]={}
                Present_vulnerability[vulnerability_key]['urls'][url_id]['request_type']=rdetails[
                    'method']

                Present_vulnerability[vulnerability_key]['urls'][url_id]['url_id']=url_id
                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']={}

                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['parameter_name']=rdetails[
                    'attack_parameter']
                parameter_id='parameter_'+str(count)
                # fp.write(f"{url_id}:{rdetails['url']} :{rdetails['attack_parameter']}\n")

                Present_vulnerability[vulnerability_key]['urls'][url_id]['url']=rdetails['url'].split("?")[0]

                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['summary']={}
                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['summary']['uid']=rdetails[
                    'uid']
                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['parameter_id']=parameter_id
                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['summary']['http_response_code']=\
                    rdetails['response']
                Present_vulnerability[vulnerability_key]['urls'][url_id]['parameter']['summary']['http_response']=\
                    rdetails['http_response']
                if 'header_parameter' in rdetails.keys():
                    Present_vulnerability[vulnerability_key]['urls'][url_id]['header']={}
                    Present_vulnerability[vulnerability_key]['urls'][url_id]['header'][rdetails['header_parameter']]=\
                        rdetails['attack_parameter']
                count+=1

                ######### CVSS #########
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['cvss']={}
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['cvss'][
                    rdetails['capec_id']]={}
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['cvss'][rdetails['capec_id']][
                    'cvss_id']=score
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['cvss'][rdetails['capec_id']][
                    'cvss_serverity']=severity.lower()
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['cvss'][rdetails['capec_id']][
                    'cvss_score']=score
                ########################

                Present_vulnerability[vulnerability_key]['risk_factor']=severity.lower()
                # f.write(f"{str(Present_vulnerability[rdetails['vulnerability']]['vulnerability_classification']['capec'][rdetails['capec_id']]['capec_description'])} = {capec_discription}\n")

                Present_vulnerability[vulnerability_key]['vulnerability_classification']['capec'][
                    rdetails['capec_id']]={}
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['capec'][
                    rdetails['capec_id']]["capec_id"]=rdetails['capec_id']
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['capec'][
                    rdetails['capec_id']][
                    "capec_description"]=copy(capec_discription[rdetails[
                    'capec_id']])  # rdetails['capec_description']                # Present_vulnerability[rdetails['vulnerability']]['vulnerability_classifications']['capec'][i['capec_id']]['capec_id'] = i['capec_id']
                # f.write(f"{str(Present_vulnerability)}\n")

                # check if cwe mapping exists
                if int(rdetails['capec_id']) in was.was['capec_cwe_mapping']:
                    cwe_id=was.was['capec_cwe_mapping'][int(rdetails['capec_id'])]
                    self.cwe_dict[rdetails['vulnerability']]+=1
                    if cwe_id in was.was['cwe_id_desc']:
                        Present_vulnerability[vulnerability_key]['vulnerability_classification']['cwe'][
                            str(cwe_id)]={}
                        Present_vulnerability[vulnerability_key]['vulnerability_classification']['cwe'][
                            str(cwe_id)]["cwe_id"]=cwe_id
                        Present_vulnerability[vulnerability_key]['vulnerability_classification']['cwe'][
                            str(cwe_id)]["cwe_description"]=was.was['cwe_id_desc'][cwe_id]

                Present_vulnerability[vulnerability_key]['vulnerability_classification']['owasp']={}
                Present_vulnerability[vulnerability_key]['vulnerability_classification']['owasp'][
                    owasp_distrubution[rdetails['vulnerability']]['owasp_id']]=owasp_distrubution[
                    rdetails['vulnerability']]

                report['services'][rdetails['service']]['vulnerabilities']=Present_vulnerability
                # self.cwe_dict[rdetails['vulnerability']]= cwe_count
                url_no+=1

            # changedbyPT
            report['vulnerability_distribution']['total_alerts']=report['vulnerability_distribution']['severity'][
                                                                     "critical"]+\
                                                                 report['vulnerability_distribution']['severity'][
                                                                     "high"]+\
                                                                 report['vulnerability_distribution']['severity'][
                                                                     "medium"]+\
                                                                 report['vulnerability_distribution']['severity'][
                                                                     "low"]

            report_coll=self.mongo.create_collection(db,'reports')
            # app_data = self.mongo.find_document(report_coll, {'application_id': self.application_id})
            # if app_data != "document_not_found":
            #     self.log.info("Found existing report in database")
            #     report_coll.delete_one({"application_id": self.application_id})
            #     self.log.info("Removed existing report in database")

            status=self.mongo.insert_document(report_coll,report)

            if status=='insert_success':
                self.log.info(f"Report successfully generated")
                self.Update_Attack_status(
                    redis_update="completed",
                    attack_state='completed',
                    detail_state='report_ready',
                    message=f"Report generation for application {self.app_name} completed",
                    subject=f"Report generation completed for App: {self.app_name}",
                    operation="Report"
                )
                # self.Update_Attack_status(attack_state='completed', detail_state='report_ready')
                # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='completed')
                # message = f"Report generation for application {self.app_name} ({self.application_id}) completed"
                # subject = f"Report generation completed"
                # util.Notification().send_notification(message=message,
                #                                         application_id=self.application_id,
                #                                         operation='Report',
                #                                         application_name=self.app_name,
                #                                         subject=subject)
                #########################################
                cache_channel.hset('dashboard','threshold',90)
                dash.Dashboard().application_count(self.application_id)
                dash.Dashboard().oneApllication(self.application_id,self.cwe_dict)
                dash.Dashboard().scanAgingHistory(self.application_id)
                dash.Dashboard().vulnerableApplications(self.application_id)
                dash.Dashboard().Heatmap_oneApplication(self.application_id)
                dash.Dashboard().total_count('all')
                dash.Dashboard().vulnerableApplications('all')
                dash.Dashboard().scanAgingHistory('all')
                dash.Dashboard().allApllication()
                dash.Dashboard().Heatmap_allApplication()
                # dashboard
                return 'attack_complete_successful'
            else:
                self.log.critical(f"Report could not successfully generated")
                return status
            # else:
            #     #Murali Change: Stale state
            #     ###########################
            #     self.Update_Attack_status(attack_state='aborted', detail_state='aborted')
            #     self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
            #     message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as no incidents were registerd from CMS"
            #     util.Notification().send_notification(message=message,
            #                                             application_id=self.application_id,
            #                                             operation='Report',
            #                                             application_name=self.app_name)
            #     ###########################
            #     self.log.info(f"Report not generated as nothing was found from CMS/AE log")
            #     self.log.critical(f"Report not generated as nothing was found from CMS/AE log")
            #     return 'failure'

        except Exception as err:
            self.log.error(err)
            self.Update_Attack_status(
                redis_update="report_generation",
                attack_state='report_generation',
                detail_state='report_aborted',
                message=f" Error in Report generation operation for application {self.app_name}",
            )
            # self.redis.set_status_value(cache_channel,'attack',self.application_id,attack_state='aborted')
            # self.Update_Attack_status(attack_state= 'aborted',detail_state='aborted')
            # message = f"Report generation operation aborted for application {self.app_name} ({self.application_id}) as exception was raised"
            # util.Notification().send_notification(message=message,
            #                                         application_id=self.application_id,
            #                                         operation='Report',
            #                                         application_name=self.app_name)
            # self.log.error(err)
            # traceback.print_stack(err)
            # return 'failure'
        finally:
            self.set_cms_to_attack_done()
            cache_channel.hdel(self.application_id,'known_incidents',str(known_incidents))
            cache_channel.hdel(self.application_id,'not_instrumented')
            cache_channel.hdel(self.application_id,'instrumented')
            if "known_incidents" in locals():
                del known_incidents
            if "all_vulnerabilities" in locals():
                del all_vulnerabilities
            if "vulnerabilities" in locals():
                del vulnerabilities
            if "report" in locals():
                del report
            if db_channel:
                db_channel.close()

    def report_for_exception(self,message,ex_time=0):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            app_store=self.mongo.create_collection(db,'applications')
            app_data=self.mongo.find_document(app_store,{'application_id':self.application_id})
            url_store_coll=self.mongo.create_collection(db,'url_store')
            url_store=self.mongo.find_document(url_store_coll,{'application_id':self.application_id})
            
            report={}
            count=0
            error_urls_dict={}
            self.cwe_dict={}
            error_display=[]
            report['report_id']=util.Authentication().generate_uuid('uuid4')
            report['report_name']=f"{app_data['detail']['name']}_{app_data['detail']['version']}"
            report['report_version']="1.0.0"

            report['application_id']=self.application_id
            report['application_details']={}
            report['application_details']['application_id']=self.application_id
            report['application_details']['application_name']=app_data['detail']['name']
            report['application_details']['application_version']=app_data['detail']['version']
            report['application_details']['application_url']=url_store['authentication']['homepage_url']
            report['application_details']['application_user']=''
            report['application_details']['scan_start_time']=app_data['attack']['attack_instantiated']
            report['application_details']['scan_end_time']=time.time()
            report['application_details']['scan_datetime']=time.time()  # app_data['attack']['attack_completed']
            # if message=='':
            #     report['application_details']['message']='Exception raised while generating report'

            # else:
            #     report['application_details']['message']=message

            if self.current_attack_user=="user_0":
                self.current_attack_user="anonymous"

            report['application_details']['user_credentials_used']=self.current_attack_user

            if cache_channel.exists('current_user'):
                scan_user=cache_channel.hget('current_user','username').decode('utf-8')

            report['application_details']['scan_profile']=scan_user
            report['application_details']['was_instance']=was.was["host_ip"]
            report['services']={}
            report['vulnerability_distribution']={}
            report['vulnerability_distribution']['severity']={}

            report['vulnerability_distribution']['severity']["critical"]=0
            report['vulnerability_distribution']['severity']["high"]=0
            report['vulnerability_distribution']['severity']["medium"]=0
            report['vulnerability_distribution']['severity']["low"]=0
            report['vulnerability_distribution']['severity']["info"]=0
            report['vulnerability_distribution']['total_alerts']=0
            
            try:
                output_message = self.message_block(message,ex_time)
                report['messages']= output_message['messages']
                
            except Exception as e:
                self.log.error(f"Exception raised as {e}")
                report['messages']={}
                report['messages']['msg'] = []
                report['messages']['msg'].append({'message_id':'message_0',
                                      'message_details':'Exception Raised While Creating Reports.',
                                      'timestamp':float(time.time())})
                report['messages']['msg_summery'] = message
            
            crawled=0
            for i,j in url_store['urls'][self.attack_user].items(): crawled+=len(j)
            report['vulnerability_distribution']['urls_crawled']=crawled
            report_coll=self.mongo.create_collection(db,'reports')
            status=self.mongo.insert_document(report_coll,report)

            if status=='insert_success':
                self.log.info(f"Report successfully generated")
                self.Update_Attack_status(
                    redis_update="completed",
                    attack_state='completed',
                    detail_state='report_ready',
                    message=f"Report generation for application {self.app_name} completed",
                    subject=f"Report generation completed for App: {self.app_name}",
                    operation="Report"
                )
            cache_channel.hset('dashboard','threshold',90)
            dash.Dashboard().application_count(self.application_id)
            dash.Dashboard().oneApllication(self.application_id,self.cwe_dict)
            dash.Dashboard().scanAgingHistory(self.application_id)
            dash.Dashboard().vulnerableApplications(self.application_id)
            dash.Dashboard().Heatmap_oneApplication(self.application_id)
            dash.Dashboard().total_count('all')
            dash.Dashboard().vulnerableApplications('all')
            dash.Dashboard().scanAgingHistory('all')
            dash.Dashboard().allApllication()
            dash.Dashboard().Heatmap_allApplication()
            # dashboard
            return 'attack_complete_successful'
        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)
        finally:
            cache_channel.hdel(self.application_id,'not_instrumented')
            cache_channel.hdel(self.application_id,'instrumented')
            self.set_cms_to_attack_done()
            if "report" in locals():
                del report
            if db_channel:
                db_channel.close()

    def generate_cvss_severity(self,current_vul_type,threat):
        try:
            cvss_base_score_dict=was.was["cvss_base_score_dict"]
            av=cvss_base_score_dict['Attack Vector']
            ac=cvss_base_score_dict['Attack Complexity']
            pr=cvss_base_score_dict['Privileges Required']
            ui=cvss_base_score_dict['User Interaction']
            # a = cvss_base_score_dict['Availability Impact']
            # s = cvss_base_score_dict['Scope']
            # c = cvss_base_score_dict['Confidentiality Impact']
            # i = cvss_base_score_dict['Integrity Impact']
            if threat=="ATTACK":
                if 'sqli' in current_vul_type:
                    s="S:C"
                    i="I:H"
                    c="C:H"
                    a="A:H"

                elif 'cmdi' in current_vul_type:
                    s="S:C"
                    i="I:H"
                    c="C:H"
                    a="A:H"

                elif 'pathtraversal' in current_vul_type:
                    s="S:U"
                    i="I:N"
                    c="C:H"
                    a="A:N"

                elif 'capec-a7-reflectivexss' in current_vul_type:
                    # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
                    s="S:C"
                    i="I:L"
                    c="C:L"
                    a="A:N"
                    # pr= "PR:N"
                    # ui = "UI:R"

                elif 'rfi' in current_vul_type:
                    s="S:C"
                    i="I:H"
                    c="C:H"
                    a="A:H"

                else:
                    s="S:U"
                    i="I:L"
                    c="C:H"
                    a="A:H"

                cvss_base_vector="CVSS:3.0/{}/{}/{}/{}/{}/{}/{}/{}".format(av,ac,pr,ui,s,c,i,a)
                c=CVSS3(cvss_base_vector)
                cvss_score=c.scores()[0]
            # if threat== "THREAT":
            #     cvss_score= (cvss_score + (cvss_score-1.5))/2

            if threat=="THREAT":
                av="AV:P"
                s="S:C"
                i="I:L"
                c="C:N"
                a="A:N"
                cvss_base_vector="CVSS:3.0/{}/{}/{}/{}/{}/{}/{}/{}".format(av,ac,pr,ui,s,c,i,a)
                c=CVSS3(cvss_base_vector)
                cvss_score=c.scores()[0]

            cvss_severity=""
            if 0.1<=cvss_score<=3.9:
                cvss_severity="Low"

            elif 4.0<=cvss_score<=6.9:
                cvss_severity="Medium"

            elif 7.0<=cvss_score<=8.9:
                cvss_severity="High"

            elif 9.0<=cvss_score<=10.0:
                cvss_severity="Critical"
            else:
                cvss_severity="Critical"

            return cvss_severity,cvss_score
        except Exception as err:
            self.log.error(err)
            traceback.print_stack(err)
        traceback.print_exc()

    # @profile(precision=4,stream=open('memory_profiler_fuzzy_header.log','a'))
    def fuzzy_header(self):
        try:
            http_session=self.app_active_session
            db_field={}
            db_field[f'urls.{self.attack_user}']=True
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.log.info(f"Creating complete list of URLs with parameters")
            url_store=self.mongo.find_document(self.url_store,{'application_id':self.application_id},db_field)
            for k1,v1 in url_store['urls'].items():
                if k1==self.attack_user:
                    for k2,v2 in v1.items():
                        for k3,v3 in v2.items():
                            attack_map=dict()
                            attack_map['session']=http_session
                            attack_map['method']=v3['requestType'].upper()
                            attack_map['url']=""
                            attack_map['url_id']=k3
                            attack_map['payload']=None
                            attack_map['service']=k2
                            parent_url=f"{v3['attack_url']}"
                            temp_url,temp_symbol="",""
                            if v3['parameters']:
                                if (attack_map['method']=='GET'):
                                    for k,v in v3['parameters'].items():
                                        temp_url+=f"{temp_symbol}{k}={v}"
                                        temp_symbol="&"
                                    else:
                                        parent_url=f"{parent_url}?{temp_url}"
                                if (attack_map['method']=='POST'):
                                    attack_map['payload']=v3['parameters']
                            else:
                                parent_url=f"{parent_url}?{temp_url}"
                            attack_map['url']=parent_url
                            attack_map['header']=v3['header']
                            if not self.attack_with_fuzzy_header(cache_channel,attack_map):
                                return False
        except Exception as e:
            self.log.critical(f"Attack for Header Aborted!: Exception raised: {e}")
            self.Update_Attack_status(redis_update="report_generation",attack_state='report_generation',
                detail_state='aborted',
                message="Attack partially completed as Exception raised",
                subject=f"Attack partially completed for App: {self.app_name}"
            )
            return False
        return True

    def attack_with_fuzzy_header(self,cache_channel,http_request):
        try:
            header_list=self.get_header_list(http_request)
            header=http_request['session'].headers
            for p in self.payload_list:
                http_request['vulnerability']=p[0]
                for data in p[1]:  # Looping each payload in a each vulerability
                    for capec_id,payload in data.items():
                        for h in header_list:
                            #if self.cms.check_cms_value(application_id=self.application_id, app_name=self.app_name):
                            self.count+=1
                            header[
                                'virsec-uid']=f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}#HEADER_ATTACK#{self.generate_uuid()}"
                            for k,v in http_request['header'].items():
                                if k==h:
                                    header[h]=payload.strip()
                                else:
                                    header[k]=v.strip()
                            http_request['header']=header
                            http_request['cookie']=None
                            http_request['verify']=False
                            response=self.perform_request(http_request)
                            if response==None:
                                self.error_urls.append(f"{http_request['url']} REASON: {self.request_exception_reason}")

                            elif response.status_code in was.configuration["report"]["error_codes"]:
                                self.error_urls.append(f"{http_request['url']} CODE: {response.status_code}")
                                response=self.perform_request(http_request)

                            if response!=None and response.status_code in was.configuration["report"][
                                "inclusion_status_codes"]:
                                self.attack_progress()
                                self.log.info(
                                    f"Generating WAS header attack for url {http_request['url']} | request{self.count}")
                                cache_map=dict()
                                cache_map['request_id']=f"request{self.count}"
                                cache_map['uid']=header['virsec-uid']
                                cache_map['method']=http_request['method']
                                cache_map['url']=http_request['url']
                                cache_map['vulnerability']=http_request['vulnerability']
                                cache_map['service']=http_request['service']
                                cache_map['response']=response.status_code  # chg
                                # cache_map['response_content'] = compress(bytes("\\n".join(str(response.content).split("\\n")[0:2]),encoding='utf8'))
                                cache_map['response_content']=str(response.content)[0:50]
                                cache_map['header_parameter']=h
                                cache_map['attack_parameter']=""
                                cache_map['attack_payload']=payload.strip()
                                cache_channel.hset(self.application_id,f"request{self.count}",str(cache_map))
                                cache_channel.hset(self.application_id,f"request{self.count}_payload",str(data))
                                # with open("./fired_urls.txt", 'a') as f:
                                #     f.write(f"###########Header Attack##############\n")
                                #     f.write(f"URL: {str(http_request['url'])}\n")
                                #     f.write(f"Payload: {http_request['payload']}\n")
                                #     f.write(f"header: {str(header)}\n")
                                #     f.write(f"method: {http_request['method']}\n")
                            # time.sleep(1)
                            # else:
                            #     self.Update_Attack_status(
                            #         redis_update="aborted",
                            #         attack_state='aborted',
                            #         detail_state='aborted',
                            #         message="Attack aborting as App status in CMS was not in 'NORMAL'/'THREAT'/'ATTACK'",
                            #         subject=f"Attack aborted for App: {self.app_name}"
                            #     )
                            #     return False
            # self.attack_for_cookie(cache_channel, http_request)
        except Exception as e:
            self.log.critical(f"Attack for Header Aborted!: Exception raised: {e}")
            self.Update_Attack_status(redis_update="report_generation",attack_state='report_generation',
                detail_state='aborted',
                message="Attack partially completed as Exception raised in header attack",
                subject=f"Attack partially completed for App: {self.app_name}"
            )
            return False
        return True

    def get_header_list(self,http_request):
        # headers=["vector"]
        no_attack_list=self.get_list_no_header_attack()
        headers=[]
        headers.extend([i for i in http_request['header'].keys() if i not in no_attack_list])
        # headers.append([i for i in http_request['header'].keys() if i != "Cookie"])
        return headers

    def attack_for_cookie(self,cache_channel,http_request):
        if ("Cookie" in http_request['header'].keys()):
            cookie_delimiter=";"
            cookie_attack_params=http_request['header']['Cookie'].replace(" ","").split(cookie_delimiter)
            cookie_regex=r"(?<=\=).*(?=\;?)"
            for p in self.payload_list:
                http_request['vulnerability']=p[0]
                for data in p[1]:  # Looping each payload in a each vulerability
                    for capec_id,payload in data.items():
                        for param in cookie_attack_params:
                            cookie_value=http_request['session'].cookies.get_dict()
                            header={}
                            # header=http_request['session'].headers
                            for k,v in http_request['header'].items():
                                if (k!='Cookie'):
                                    header[k]=v.strip()
                            self.count+=1
                            header[
                                'virsec-uid']=f"was#{self.application_id}#{http_request['url_id']}#{http_request['vulnerability']}#{capec_id}#request{self.count}#{http_request['service']}#{http_request['method']}#COOKIE_ATTACK#{self.generate_uuid()}"
                            new_cookie_value=re.sub(cookie_regex,payload,param)
                            cookie_value[new_cookie_value.split('=')[0]]=new_cookie_value.split('=')[1]
                            http_request['header']=header
                            http_request['cookie']=cookie_value
                            http_request['verify']=False
                            response=self.perform_request(http_request)
                            # response = http_request['session'].request(
                            #     method=http_request['method'],
                            #     url=http_request['url'],
                            #     data=http_request['payload'],
                            #     headers=header,
                            #     cookies=cookie_value,
                            #     verify=False
                            # )
                            if response==None:
                                self.error_urls.append(f"{http_request['url']} REASON: {self.request_exception_reason}")

                            elif response.status_code in was.configuration["report"]["error_codes"]:
                                self.error_urls.append(f"{http_request['url']} CODE: {response.status_code}")
                                response=self.perform_request(http_request)

                            if response!=None and response.status_code in was.configuration["report"][
                                "inclusion_status_codes"]:
                                self.attack_progress()
                                cache_map=dict()
                                cache_map['request_id']=f"request{self.count}"
                                cache_map['uid']=header['virsec-uid']
                                cache_map['method']=http_request['method']
                                cache_map['url']=http_request['url']
                                cache_map['vulnerability']=http_request['vulnerability']
                                cache_map['service']=http_request['service']
                                cache_map['response']=response.status_code  # chg
                                cache_channel.hset(self.application_id,f"request{self.count}",str(cache_map))
                                cache_channel.hset(self.application_id,f"request{self.count}_payload",str(data))
                                # with open("./fired_urls.txt", 'a') as f:
                                #     f.write(f"###########Cookie Attack##############\n")
                                #     f.write(f"URL: {str(http_request['url'])}\n")
                                #     f.write(f"Payload: {http_request['payload']}\n")
                                #     f.write(f"header: {str(header)}\n")
                                #     f.write(f"method: {http_request['method']}\n")
                                #     f.write(f"cookies: {str(cookie_value)}\n")
                                #     f.write(f"response: {str(response.status_code)}\n")

    def get_list_no_header_attack(self):
        return ['Cookie','Host','User-Agent','Pragma']

    def perform_request(self,http_request):
        try:
            # Workaroud
            self.request_exception_reason=""
            run_id=self.generate_uuid()
            http_request['header']["user-agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
            # Workaroud completed
            self.log.info(f"{run_id}: Raising request for {str(http_request)}")
            response=http_request['session'].request(
                method=http_request['method'],
                url=http_request['url'],
                # Workaroud
                data=http_request['payload'],
                # Workaroud completed
                headers=http_request['header'],
                cookies=http_request['cookie'],
                verify=http_request['verify'],
                timeout=was.configuration["attack"]["attack_timeout"]
            )
            if response.status_code in [400,500,501,502,503]:
                response=http_request['session'].request(
                    method=http_request['method'],
                    url=http_request['url'],
                    # Workaroud
                    data=json.dumps(http_request['payload']),
                    # Workaroud completed
                    headers=http_request['header'],
                    cookies=http_request['cookie'],
                    verify=http_request['verify'],
                    timeout=was.configuration["attack"]["attack_timeout"]
                )
            self.log.info(f"{run_id}: Attack Response Code: {response.status_code}")
            
            # with open("req_res_log.log","a") as f:
                
            #     f.write(f"Run ID: {run_id}\n")
            #     f.write(f"Code: {response.status_code}\n")
            #     f.write(f"URL: {response.url}\n")
            #     f.write(f"Method: {http_request['method']}\n")
            #     f.write(f"Response\nHeader: {response.headers}\n")
            #     f.write(f"Body: {response.text}\n")
                
            #     f.write(f"Request\nHeader: {response.request.headers}\n")
            #     f.write(f"Body: {response.request.body}\n")
            #     f.write("#######################################\n")
            # if response.status_code in was.configuration["report"]["error_codes"]:
            #     print(f"Error:{http_request['url']} : {response}")
            return response
        except requests.exceptions.Timeout as t:
            self.log.error(f"REQUEST-TIMEOUT for {str(http_request)}; Ignoring requesting and proceding")
            self.request_exception_reason="REQUEST-TIMEOUT"
            return None
        except client.RemoteDisconnected:
            self.log.error(f"RemoteDisconnected for {str(http_request)}")
            self.request_exception_reason="REMOTE-DISCONNECTED"
            return None
        except Exception as e:
            self.log.critical(f"Attack Exception raised: {str(e)}")
            self.request_exception_reason="EXCEPTION"
            return None
        
    def perform_request_251(self,http_request,counter=0):
        try:
            # Workaroud
            #http_request['header']["user-agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
            # Workaroud completed
            self.log.info(f"Raising request for {str(http_request)}")
            response=http_request['session'].request(
                method=http_request['method'],
                url=http_request['url'],
                # Workaroud
                #data=json.dumps(http_request['payload']),
                data=http_request['payload'],
                # Workaroud completed
                headers=http_request['header'],
                cookies=http_request['cookie'],
                verify=http_request['verify'],
                timeout=was.configuration["attack"]["attack_timeout"]
            )
            # run_id=self.generate_uuid()
            # with open("req_res_log.log","a") as f:
            #     f.write(f"Run ID: {run_id}\n")
            #     f.write(f"Code: {response.status_code}\n")
            #     f.write(f"URL: {response.url}\n")
            #     f.write(f"Method: {http_request['method']}\n")
            #     f.write(f"Response\nHeader: {response.headers}\n")
            #     f.write(f"Body: {response.text}\n")
                
            #     f.write(f"Request\nHeader: {response.request.headers}\n")
            #     f.write(f"Body: {response.request.body}\n")
            #     f.write("#######################################\n")
            # #self.perform_request(http_request=http_request,counter=counter+1)
            # # if(response.status_code==302 and "Set-Cookie" in response.headers.keys() and counter < 5):
            # #     new_session=self.authenticate_application()
            # #     if new_session != None:
            # #         http_request['session']=new_session
            # #         self.perform_request(http_request=http_request,counter=counter+1)
            # print(response.status_code)
            self.log.info(f"Attack Response Code: {response.status_code}")
            if response.status_code in was.configuration["report"]["error_codes"]:
                print(f"Error:{http_request['url']} : {response}")
            return response
        except requests.exceptions.Timeout as t:
            self.log.info(f"REQUEST-TIMEOUT for {str(http_request)}; Ignoring requesting and proceding")
            return None
        except client.RemoteDisconnected:
            self.log.info(f"RemoteDisconnected for {str(http_request)}")
            return None
        except Exception as e:
            self.log.critical(f"Attack Exception raised: {str(e)}")
            return None

    def attack_progress(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            cache_map={}
            cache_map['application_id']=self.application_id
            para_count=list(map(lambda x:x*self.paloadprogress_count,self.urlprogress_count))
            parameter_count=sum(para_count)

            h_count=list(map(lambda x:x*self.paloadprogress_count,self.header_length))
            header_count=sum(h_count)
            total=parameter_count+header_count
            progress=int((self.count/total)*100)
            if progress<99:
                cache_map['attack_state']='in_progress'
                cache_map['attack_progress']=progress
                cache_channel.hmset('attack',{self.application_id:str(cache_map)})
            else:
                progress=99
                cache_map['attack_state']='in_progress'
                cache_map['attack_progress']=progress
                cache_channel.hmset('attack',{self.application_id:str(cache_map)})

        except Exception as e:
            self.log.error(f"Progress Exception raised: {str(e)}")
            return None

    def update_cache(self,state_key="",cache_update=""):
        state_pick={
            "attack":'attack_state',
            "crawl":'crawl_state'
        }
        if self.cache_channel==None:
            cache_channel=self.redis.connect(host=was.was['cache'])
            self.cache_channel=cache_channel
        if cache_update!="":
            attack_state=state_pick.get(state_key,"NO_STATE")
            if attack_state!="NO_STATE":
                cache_map=dict()
                cache_map['application_id']=self.application_id
                cache_map={'application_id':self.application_id,'attack_state':cache_update}
                self.cache_channel.hmset('attack',{self.application_id:str(cache_map)})
                self.cache_channel.hset(self.application_id,'attack_state',cache_update)
                return True
            self.log.error(f"Cache update failed! State key found {state_key}")
            return False
        self.log.error(f"Cache update failed! cache value found {cache_update}")
        return False

    def parse_log_new(self,log_path):
        try:
            with open(log_path,'r') as f:
                line_nums=[]
                search_phrase1="ActiveMQ_Mgr::send: JSON: (MsgSeq#"
                search_phrase2="Dest: DBI-CMS-QUEUE): {"  # "Dest: SW-EXC-LOG-QUEUE"

                line_num=0
                for line in f.readlines():
                    line_num+=1
                    if (line.find(search_phrase1)>=0) and line.find(search_phrase2)>=0:
                        line_nums.append(line_num)  # print line_num

            f=open(log_path,'r')
            line_data=f.readlines()
            log_map={}
            for index,line in enumerate(line_nums):
                temp_uuid=None
                temp_virsecuid=""
                next_line_count=30
                bUUID=True
                sUUID=""
                bLevel=True
                sLevel=""
                bThreat_desc=True
                sThreat_desc=""
                bRequestId=True
                sRequestId=""
                bVirsec_uid=True
                sVirsec_uid=""
                bUser_id=True
                sUser_id=""
                bTs=True
                sTs=""
                try:
                    next_line_count=line_nums[index+1]
                except IndexError:
                    next_line_count=line+30
                except Exception:
                    print("here")
                # Iterate to the next line until i find uuid
                for loopline in range(1+line,next_line_count):
                    linevalue=(line_data[loopline])

                    if "ActiveMQ_Mgr::send: JSON: (MsgSeq" in linevalue:
                        break
                    if linevalue.strip()=="}":
                        break

                    if "uuid" in linevalue:
                        if bUUID:
                            temp_uuid=(linevalue.strip(",").strip().split(":"))[1]
                            temp_uuid=temp_uuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            bUUID=False
                            sUUID=temp_uuid

                    if '"level" :' in linevalue or '"level":' in linevalue:
                        if bLevel:
                            bLevel=False
                            temp=(linevalue.strip(",").strip().split(":"))[1]
                            temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            sLevel=temp

                    if "threat_desc" in linevalue:
                        if bThreat_desc:
                            bThreat_desc=False
                            temp=(linevalue.strip(",").strip().split(":"))[1]
                            temp=temp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            sThreat_desc=temp

                    if "RequestId" in linevalue:
                        if bRequestId:
                            bRequestId=False
                            req=(linevalue.strip(",").strip().split(":"))[1]
                            req=req.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            sRequestId=req

                    if "virsec-uid" in linevalue:
                        if bVirsec_uid:
                            bVirsec_uid=False
                            temp_virsecuid=(linevalue.strip(",").strip().split(":"))[1]
                            temp_virsecuid=temp_virsecuid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            sVirsec_uid=temp_virsecuid

                    if "user_id" in linevalue:
                        if bUser_id:
                            bUser_id=False
                            temp_userid=":".join((linevalue.strip(",").strip().split(":"))[1:])
                            temp_userid=temp_userid.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            sUser_id=temp_userid

                    if "ts" in linevalue:
                        if bTs:
                            bTs=False
                            temp_timestamp=":".join((linevalue.strip(",").strip().split(":"))[1:])
                            temp_timestamp=temp_timestamp.strip('"').strip(' ').strip('"').strip(",").strip('"')
                            if "T" in temp_timestamp:
                                sTs=temp_timestamp

                if not (bVirsec_uid) and not (bUUID):
                    request_num=int((sVirsec_uid.split('#')[5]).replace("request",""))
                    log_map[sVirsec_uid+"_"+str(sRequestId)]={
                        "uuid":sUUID,
                        "level":sLevel,
                        "threat_desc":sThreat_desc,
                        "RequestId":request_num,
                        "user_id":sUser_id,
                        "virsec_uid":sVirsec_uid,
                        "ts":sTs
                    }
            f.close()
            self.uuids=list(log_map.keys())
            return log_map

        except Exception as err:
            self.log.error(err)
            return None

    def generate_uuid(self):
        return str(uuid.uuid4().hex)

    def set_cms_to_attack_done(self):
        cache_channel=self.redis.connect(host=was.was['cache'])
        cache_channel.hset(self.application_id,"attack_status",str({"attack_status":"ATTACK_DONE"}))
        return True

    def fetch_incidents(self,header):
        cms_incidents=[]
        incidents_data=[]
        if not self.cms.check_cms_value(application_id=self.application_id,app_name=self.app_name):
            util.Notification().send_notification(
                    message=f"Application {self.app_name} not found in Normal/Attack/Threat during attack; Fetching from both archive and regular."\
                        "Report generation time may increase!",
                    application_id=self.application_id,
                    operation="Report",
                    application_name=self.app_name,
                    subject=f"{self.app_name} switching to both archived and regular for fetching incidents"
                )
            
            incidents_data=self.cms.application_details_from_archived(
                                    header,
                                    self.application_id,
                                    start_time=self.attack_start_time,
                                    end_time=self.report_start_time)
            if incidents_data in ["invalid_application","internal_server_error","exception",None]:
               util.Notification().send_notification(
                    message=f"Application {self.app_name} unable to process archived incidents,continuing to fetch regular incidents.",
                    application_id=self.application_id,
                    operation="Report",
                    application_name=self.app_name,
                    subject=f"{self.app_name} switching to both archived and regular for fetching incidents"
                )
               self.log.error(f"Unable to process archived incidents; returned: {incidents_data}")
            if isinstance(incidents_data,list):
                cms_incidents.extend(incidents_data)
        
        incidents_data=[]
        incidents_data=self.cms.application_incidents_all(self.application_id,
                            header,
                            return_empty_response=True)
        if incidents_data in ['connection_error','invalid_application',None,"cms_fetch_error","cms_token_expired"]:
            util.Notification().send_notification(
                    message=f"Application {self.app_name}Unable to process regular incidents.",
                    application_id=self.application_id,
                    operation="Report",
                    application_name=self.app_name,
                    subject=f"{self.app_name} switching to both archived and regular for fetching incidents"
                )
            self.log.error(f"Unable to process regular incidents; returned: {incidents_data}")
            return False
        if isinstance(incidents_data,list):
            cms_incidents.extend(incidents_data)
        return cms_incidents
        
        
        # cms_incidents=self.cms.application_incidents_all(self.application_id,
        #         header,
        #         return_empty_response=True)    
        # if self.cms.check_cms_value(application_id=self.application_id,app_name=self.app_name):
        #     cms_incidents=self.cms.application_incidents_all(self.application_id,
        #         header,
        #         return_empty_response=True)
        #     if cms_incidents==False:
        #         util.Notification().send_notification(
        #             message=f"Application {self.app_name} not in Normal/Attack/Threat; Switching to archive to fetch incidents",
        #             application_id=self.application_id,
        #             operation="Report",
        #             application_name=self.app_name,
        #             subject=f"{self.app_name} switching to archive for fetching icnidents"
        #         )
        #         cms_incidents=self.cms.application_details_from_archived(
        #             header,
        #             self.application_id,
        #             start_time=self.attack_start_time,
        #             end_time=self.report_start_time)
        #     self.cms_not_ok=False
        # else:
        #     util.Notification().send_notification(
        #         message=f"Application {self.app_name} not in Normal/Attack/Threat; Switching to archive to fetch incidents",
        #         application_id=self.application_id,
        #         operation="Report",
        #         application_name=self.app_name,
        #         subject=f"{self.app_name} switching to archive for fetching icnidents"
        #     )
        #     cms_incidents=self.cms.application_details_from_archived(
        #         header,
        #         self.application_id,
        #         start_time=self.attack_start_time,
        #         end_time=self.report_start_time)
        #     self.cms_not_ok=True
        # return cms_incidents

    def fetch_each_incident_detail(self,header,incident):
        incident_detail={}
        if not self.cms.check_cms_value(application_id=self.application_id,app_name=self.app_name):
            incident_detail=self.cms.application_archived_incident_detail(self.application_id,header,incident,
                    return_empty_response=False)
            if incident_detail == "cms_no_data":
                incident_detail=self.cms.application_incident_detail(self.application_id,header,incident,
                                    return_empty_response=True)
                if isinstance(incident_detail,dict):
                    return incident_detail
                if incident_detail == "cms_no_data":
                    incident_detail={}
                else:
                    self.log.error(f"Unable to process CMS incident, incident ID: {incident}; response: {incident_detail}")
                    return False
                
            else:
                if isinstance(incident_detail,dict):
                    return incident_detail
                self.log.error(f"Unable to process Archived CMS incident, incident ID: {incident}; response: {incident_detail}; Switching to CMS incidents")
        incident_detail=self.cms.application_incident_detail(self.application_id,header,incident,
                                    return_empty_response=True)
        if incident_detail == "cms_no_data":
            incident_detail={}
        else:
            if isinstance(incident_detail,dict):
                return incident_detail
            self.log.error(f"Unable to process CMS incident, incident ID: {incident}; response: {incident_detail}")
            
        return incident_detail
        # if self.cms.check_cms_value(application_id=self.application_id,app_name=self.app_name):
        #     incident_detail=self.cms.application_incident_detail(self.application_id,header,incident,
        #         return_empty_response=True)
        #     if incident_detail=="CMS_DOWN":
        #         incident_detail=self.cms.application_archived_incident_detail(self.application_id,header,incident,
        #             return_empty_response=False)
        #     self.cms_not_ok=False
        # else:
        #     incident_detail=self.cms.application_archived_incident_detail(self.application_id,header,incident,
        #         return_empty_response=False)
        #     self.cms_not_ok=True
        # return incident_detail
    
    def authenticate_application(self):
        for login_call in self.users_login_calls[self.attack_user]["http_stream"]:
            if login_call["method"]=="POST" and "requestBody" in login_call:
                self.log.info(
                    f"Application call has been made for user: {self.attack_user} for requestID:  {login_call['requestId']} ")
                app_session=requests.Session()
                response=app_session.post(url=login_call['url'],
                    data=login_call['requestBody'],allow_redirects=True)
                if response.status_code==200:
                    self.app_active_session=app_session
                    return app_session
                else:
                    app_session.close()
        return None
