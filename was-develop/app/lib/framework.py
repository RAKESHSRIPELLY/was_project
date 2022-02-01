import copy

application_authentication_user__author__='JG'

import urllib
from lib import utility as util
from lib import api_repository as api
from lib import payload_repository as payload
from config import was,cms,environment as env
from crawl import operations as cops
import time
import os,sys
import re
from datetime import datetime,timezone
import math
import smtplib
from multiprocessing.pool import ThreadPool
from attack import operation as aops
import signal
import requests
import json
import urllib.parse as urlparse
from urllib.parse import parse_qs
import itertools
from lib import widget as dash
import random
from pymongo import MongoClient
from datetime import datetime
import pymongo
import gc
import threading
import urllib
from time import sleep
import json
import pathlib
# from dateutil import tz
# import pytz
from dateutil.tz import gettz
from functools import wraps
# cms_pool_status={}

def check_CMS_Status(method):
    @wraps(method)
    def inner1(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Querying database for applications")
            coll=self.mongo.create_collection(db,'applications')
            db_applications=self.mongo.find_all_documents(coll)
            if db_applications=='document_not_found':
                self.log.warning(f"Applications not available in database")

            self.log.info(f"Checking token expiry status")
            if cache_channel.exists('cms'):
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            else:
                self.log.critical(f"CMS is not configured to fetch applications")
                return 'cms_not_configured'
            self.log.warning(f"CMS token will expire in {cache_channel.ttl(cms['username'])} seconds")
            if cache_channel.ttl(cms['username'])>300:
                self.log.info(f"Using existing token to connect to CMS")
                user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            else:
                self.log.warning(f"Regenerating token to connect to CMS")
                status=CMS(cms['ipv4_address']).refresh_token(cms['username'])

                if status=='success':
                    self.log.info(f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                    user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                elif 'error' in status:
                    if 'captcha' in status['error_description']:
                        return 'cms_captcha_error'
                    else:
                        return 'cms_authentication_error'
            self.log.info(f"Querying CMS for applications")
            cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                cms['ipv4_address'])
            cms_applications=CMS(cms['ipv4_address']).applications(cms_services_header)
            for cms_id in cms_applications:
                status=CMS(cms['ipv4_address']).application_status(cms_id['id'],cms_services_header)
                doc=self.mongo.find_document(coll,{'application_id':cms_id['id']})
                if isinstance(doc,dict):
                    if doc['detail']['instrumentation'] != status:
                        input_str={}
                        input_str['instrumentation'] = status
                        input_str['application_id'] = cms_id['id']
                        method_output = method(self, input_str) 
        
        except Exception as e:
            return e
        
        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()
        
    return inner1 
class WAS:
    
    def __init__(self):
        self.log=util.Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()

    def authorization_token(self,user_id,timeout):
        try:
            self.log.info(f"Generating WAS authorization token")
            token=util.Authentication().generate_token(16)

            cache_channel=self.redis.connect(host=was.was['cache'])
            cache_channel.setex(user_id,timeout,token)
            return token
        finally:
            if cache_channel:
                del cache_channel

    def authorization(self,token,address):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])

            self.log.info(f"Authorizing API access for {address}")
            user_id=self.redis.get_key_from_value(cache_channel,token)
            if user_id!='key_not_found':
                self.log.debug(f"Validating authorization token")
                was_authorization_token=(cache_channel.get(user_id)).decode('utf-8')
                if cache_channel.hexists('login',was_authorization_token):
                    self.log.debug(f"Validating source address")
                    remote_address=(cache_channel.hget('login',was_authorization_token).decode('utf-8'))

                    if token==was_authorization_token and remote_address==address:
                        self.log.info(f"{user_id} authorized to access APIs from {remote_address}")
                        return 'authorized'
                    else:
                        self.log.warning(f"{user_id} unauthorized to access APIs from {remote_address}")
                        return 'unauthorized'
            else:
                self.log.info(f"WAS authorization token {token} is invalid")
                return 'token_invalid'
        finally:
            if cache_channel:
                del cache_channel

    def system_authorization(self,token,address):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Authorizing system to access APIs")
            self.log.info(f"token value : {token}")
            user_id=self.redis.get_key_from_value(cache_channel,token)
            self.log.info(f"user ID value : {user_id}")
            self.log.info(f"address value : {address}")

            if user_id!='key_not_found':
                if token==(cache_channel.get(user_id)).decode('utf-8') and user_id==address:
                    coll=self.mongo.create_collection(db,'vault')
                    doc=self.mongo.find_document(coll,{'ipv4_address':user_id},{'integration.password':1})
                    if isinstance(doc,dict):
                        password=doc['integration']['password']
                        self.log.info(f"password value : {password}")

                        validation=util.Authentication().validate_password(password,token)
                        self.log.info(f"validation value : {validation}")

                        if validation=='valid':
                            self.log.info(f"{user_id} authorized to access APIs")
                            return 'token_valid'
                        else:
                            self.log.info(f"{user_id} unauthorized to access APIs")
                            return 'token_invalid'
                    else:
                        return doc

                else:
                    self.log.warning(f"{user_id} unauthorized to access APIs")
                    return 'unauthorized'
            else:
                self.log.info(f"WAS authorization token {token} is invalid")
                return 'token_invalid'
        finally:
            if cache_channel:
                del cache_channel

    def validate_user(self,visitor_address,**kwargs):
        try:
            user_input=kwargs.get('user')

            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            if user_input['type']=='was':
                self.log.info(f"Validating WAS user")
                self.log.info(f"Checking user details with username: {user_input['username']}")

                coll=self.mongo.create_collection(db,'users')
                doc=self.mongo.find_document(coll,{"username":user_input['username']})
                if 'user_id' in doc:
                    self.log.info(f"Validating user with username: {user_input['username']}")
                    coll=self.mongo.create_collection(db,'vault')
                    doc=self.mongo.find_document(coll,{"user_id":doc['user_id']})
                    if doc!='document_not_found' or doc!='connection_error':
                        status=util.Authentication().validate_password(doc['password'],user_input['password'])
                        if status=='valid':
                            self.log.debug(f"Updating cache with token details")
                            was_authorization_token=WAS().authorization_token(doc['user_id'],10800)

                            self.log.debug(f"Updating remote-address details for {user_input['username']}")
                            cache_channel.hset('login',was_authorization_token,visitor_address)

                            coll=self.mongo.create_collection(db,'users')
                            doc=self.mongo.find_document(coll,{"username":user_input['username']})
                            if doc!='document_not_found' or doc!='connection_error':
                                users_map=dict()
                                users_map['authorization_token']=was_authorization_token
                                users_map['user_id']=doc['user_id']
                                users_map['first_name']=doc['first_name']
                                users_map['last_name']=doc['last_name']
                                users_map['username']=doc['username']
                                users_map['user_role']=doc['roles']
                                # self.log.info(f"INFO: WAS user {doc['username']} validated successfully", notify=True)
                                cache_channel.hset('current_user','username',doc['username'])

                                return 'user_validated',users_map
                            else:
                                self.log.warning(f"User with username {user_input['username']} not found")
                                return doc,None
                        else:
                            self.log.warning(f"User with username {user_input['username']} is not authorized")
                            return 'password_do_not_match',None
                    else:
                        self.log.warning(f"User with username {user_input['username']} not found")
                        return doc,None
                elif doc=='document_not_found':
                    self.log.warning(f"User with username {user_input['username']} not found")
                    return 'username_not_found',None
                elif doc=='connection_error':
                    self.log.critical(f"Could not connect to database")
                    return 'database_connection_error',None
            # elif user_input['type'] == 'cms':
            #     self.log.info(f"Validating CMS user")
            #     cache_data = util.ConvertData((cache_channel.hmget('configuration', 'cms')[0]).decode('utf-8')).framework_compatible()
            #     authentication_header = util.Authentication().create_http_header('authentication',
            #                                                                      cache_data['authorization_token'],
            #                                                                      cache_data['ipv4_address'])
            #     login_detail = CMS(cache_data['ipv4_address']).login(username=user_input['username'],
            #                                                          password=user_input['password'],
            #                                                          header=authentication_header)
            #     if 'error' in login_detail:
            #         return login_detail['error'], login_detail['error_description']
            #
            #     if cache_channel.hexists('users', 'cms'):
            #         user = util.ConvertData(cache_channel.hmget('users', 'cms')[0].decode('utf-8')).framework_compatible()
            #         if user['login_time'] and user['visitor_address']:
            #             last_login = user['login_time']
            #             last_visitor = user['visitor_address']
            #
            #     current_login = time.time()
            #     current_visitor = visitor_address
            #     self.log.info(f"Updating cache with user details")
            #     cache_map = {"username": login_detail['additionalDetails']['userId'],
            #                  "login_time": current_login,
            #                  "visitor_address": current_visitor}
            #     cache_channel.hmset('users', {'cms': str(cache_map)})
            #
            #     self.log.info(f"Updating cache with token details")
            #     was_authorization_token = WAS().authorization_token(login_detail['additionalDetails']['userId'],
            #                                                         login_detail['expires_in'])
            #
            #     cache_channel.setex(login_detail['additionalDetails']['email'], login_detail['expires_in'],
            #                         login_detail['access_token'])
            #
            #     self.log.info(f"Checking users database for {login_detail['additionalDetails']['userId']}")
            #     coll = self.mongo.create_collection(db, 'users')
            #     doc = self.mongo.find_document(coll, {'username': login_detail['additionalDetails']['email']})
            #
            #     users_map = dict()
            #     users_map['user_id'] = login_detail['additionalDetails']['userId']
            #     users_map['username'] = login_detail['additionalDetails']['email']
            #     users_map['first_name'] = login_detail['additionalDetails']['firstName']
            #     users_map['last_name'] = login_detail['additionalDetails']['lastName']
            #     users_map['type'] = user_input['type']
            #
            #     if doc != 'document_not_found' and doc['username'] == login_detail['additionalDetails']['email']:
            #         users_map.pop('type')
            #         users_map['authorization_token'] = was_authorization_token
            #         return 'success', users_map
            #     elif doc == 'document_not_found':
            #         self.log.info(f"Updating users database for {login_detail['additionalDetails']['userId']}")
            #         users_map.pop('last_login')
            #         users_map.pop('last_visitor')
            #         status = self.mongo.insert_document(coll, users_map)
            #         if status == 'insert_success':
            #             vault_map = dict()
            #             vault_map['user_id'] = login_detail['additionalDetails']['userId']
            #             vault_map['type'] = user_input['type']
            #             vault_map['password'], vault_map['key'] = util.Authentication().encrypt_password(user_input['password'])
            #
            #             self.log.info(f"Updating vault database for {login_detail['additionalDetails']['userId']}")
            #             coll = self.mongo.create_collection(db, 'vault')
            #             status = self.mongo.insert_document(coll, vault_map)
            #
            #             users_map.pop('_id')
            #             users_map.pop('type')
            #             users_map['authorization_token'] = was_authorization_token
            #             return status, users_map
            #         else:
            #             return status, None
            #     else:
            #         return doc, None
            else:
                return 'invalid_user_type'
        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()

    def change_login_credentials(self,**kwargs):
        try:
            user_input=kwargs.get('user')

            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Validating WAS user")
            self.log.info(f"Checking user details with username: {user_input['username']}")

            coll=self.mongo.create_collection(db,'users')
            doc=self.mongo.find_document(coll,{"username":user_input['username']})
            if 'user_id' in doc:
                self.log.info(f"Validating user with username: {user_input['username']}")
                coll=self.mongo.create_collection(db,'vault')
                doc=self.mongo.find_document(coll,{"user_id":doc['user_id']})
                if doc!='document_not_found' or doc!='connection_error':
                    status=util.Authentication().validate_password(doc['password'],user_input['current_password'])
                    if status=='valid':
                        if user_input['current_password']!=user_input['new_password']:
                            new_password=util.Authentication().hash_password(user_input['new_password'])

                            coll=self.mongo.create_collection(db,'vault')

                            status=self.mongo.update_document(coll,{'$set':{'password':new_password}},
                                {'user_id':doc['user_id']})
                            if status=='update_success':
                                return 'new_password_updated',None
                            else:
                                return status
                        elif user_input['current_password']==user_input['new_password']:
                            return 'same_as_old_password',None
                    else:
                        self.log.warning(f"User with username {user_input['username']} is not authorized")
                        return 'current_password_invalid',None
                else:
                    self.log.warning(f"User with username {user_input['username']} not found")
                    return doc,None
            elif doc=='document_not_found':
                self.log.warning(f"User with username {user_input['username']} not found")
                return 'username_not_found',None
            elif doc=='connection_error':
                self.log.critical(f"Could not connect to database")
                return 'database_connection_error',None

        finally:
            if cache_channel:
                del cache_channel
                
    @check_CMS_Status           
    def update_CMS_status(self,input=""):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            instrumentation = input['instrumentation']
            app_id = input['application_id']
            coll=self.mongo.create_collection(db,'applications')
            doc=self.mongo.update_document(coll,{'$set':{'detail.instrumentation':instrumentation}},
                        {'application_id':app_id},upsert=True)
            if doc == 'sucess':
                self.log.info(f"Instrumentation status updated Sucessfully{app_id}")
            
                
        except Exception as e:
            self.log.warning(f"Instrumentation status updated Unsucessful {app_id}")
            return e
        
        finally:
            if db_channel:
                db_channel.close()
                
    def logout(self,token):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            user_id=self.redis.get_key_from_value(cache_channel,token)

            db_channel=self.mongo.connect(host=was.was['database'])
            ##'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'users')
            doc=self.mongo.find_document(coll,{'user_id':user_id})
            if doc:
                if doc['type']=='was':
                    self.log.debug(f"Flushing WAS authorization token for user {user_id}")
                    status=cache_channel.set(user_id,util.Authentication().generate_random_string(32))
                    if status is True:
                        return 'success'
                    else:
                        return 'failure'
                elif doc['type']=='cms':
                    self.log.debug(f"Flushing WAS authorization token for user {user_id}")
                    cache_channel.set(user_id,util.Authentication().generate_random_string(32))

                    bearer_token=(cache_channel.get(doc['username'])).decode('utf-8')
                    cms_details=util.ConvertData(
                        (cache_channel.hmget('configuration','cms')[0]).decode('utf-8')).framework_compatible()
                    cms_services_header=util.Authentication().create_http_header('services',bearer_token,
                        cms_details['ipv4_address'])
                    status=CMS(cms_details['ipv4_address']).logout(cms_services_header)
                    if status=='success':
                        self.log.debug(f"Flushing CMS bearer token for user {doc['username']}")
                        cache_channel.set(doc['username'],util.Authentication().generate_random_string(32))
                        self.log.info(f"User {user_id} logout successful")
                    return status
            else:
                return None
        finally:
            if cache_channel:
                del cache_channel

    def dashboard(self,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            user_input=kwargs.get('dashboard')
            self.log.info(f"Fetching reports from database")
            coll=self.mongo.create_collection(db,'reports')

            application_id=user_input['application']
            self.client=MongoClient(host=was.was["database"])
            self.mydatabase=self.client['was_db']
            self.letest_report=self.mydatabase['reports']

            self.client=MongoClient(host=was.was["database"])
            reports_applications=self.mongo.find_all_documents(coll)
            
            self.applications={}
            application_set=set()
            application_list=[]
            current_app = set()
            app_coll =self.mongo.create_collection(db,'applications')
            dash_doc = self.mongo.find_documents(app_coll, {'app_present': True})
            db_applications=[]
            if cache_channel.exists('cms'):
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                current_CMS=cms['ipv4_address'].replace('.','_')
                
            for i in reports_applications:
                    application_set.add(i['application_details']['application_id'])
                    
            for i in dash_doc:
                if i['application_id'] in application_set:
                    db_applications.append(i['application_id'])
            
            if len(db_applications) > 0:
                
                    
                for i in db_applications:
                    all_rows=self.letest_report.find_one({"application_id":i},sort=[('_id',pymongo.DESCENDING)])
                    application_list.append(all_rows)

                for i in application_list:
                    appName=i['application_details']['application_name']
                    self.applications[appName]={}
                    self.applications[appName]['application_id']=i['application_details']['application_id']
                    self.applications[appName]['application_name']=appName

                for i in db_applications:
                    coll_i=self.mongo.create_collection(db,'dashboard')
                    # dash_doc = self.mongo.find_document(coll_i, {'application_id': 'all'})
                    doc=self.mongo.update_document(coll_i,{'$set':{'applications':self.applications,}},
                        {'application_id':i},upsert=True)

                doc=self.mongo.update_document(coll_i,{'$set':{'applications':self.applications,}},
                    {'application_id':'all'},upsert=True)


                coll=self.mongo.create_collection(db,'dashboard')
                dash_doc=self.mongo.find_document(coll,{'application_id':user_input['application']})

                # coll = self.mongo.create_collection(db, 'configuration')
                # config_doc = self.mongo.find_document(coll, {'api_version': '1.0'})
                if isinstance(dash_doc,dict):  # and isinstance(config_doc, dict)
                    if user_input['application'] == 'all':
                        dash_doc.pop('_id')
                        if current_CMS in dash_doc['dashboard'].keys():
                            return_map=dict()
                            return_map['applications']=dash_doc['applications']
                            return_map['dashboard']=dash_doc['dashboard'][current_CMS]
                            # return_map['threshold'] = config_doc['database_policy']['archive']
                            return return_map
                        else:
                            return_map=dict()
                            return_map['applications']=dash_doc['applications']
                            return_map['dashboard']=dash_doc['dashboard']
                            # return_map['threshold'] = config_doc['database_policy']['archive']
                            return return_map
                    else:
                        dash_doc.pop('_id')
                        return_map=dict()
                        return_map['applications']=dash_doc['applications']
                        return_map['dashboard']=dash_doc['dashboard']
                        # return_map['threshold'] = config_doc['database_policy']['archive']
                        return return_map
                if dash_doc=='document_not_found':
                    self.log.warning(f"Dashboard details not available for applications")
                    return 'data_not_available'
                # elif dash_doc=='document_not_found':
                #     self.log.warning(f"Configuration details not available for dashboard")
                #     return 'data_not_available'
            else:
                return 'success'

            



        finally:
            if db_channel:
                db_channel.close()

    def applications(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            # if 'was_db'=="":
            #     self.log.critical(f"CMS is not configured to fetch applications")
            #     return 'cms_not_configured'

            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Querying database for applications")
            coll=self.mongo.create_collection(db,'applications')
            db_applications=self.mongo.find_all_documents(coll)
            if db_applications=='document_not_found':
                self.log.warning(f"Applications not available in database")

            self.log.info(f"Checking token expiry status")
            if cache_channel.exists('cms'):
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            else:
                self.log.critical(f"CMS is not configured to fetch applications")
                return 'cms_not_configured'
            self.log.warning(f"CMS token will expire in {cache_channel.ttl(cms['username'])} seconds")
            if cache_channel.ttl(cms['username'])>300:
                self.log.info(f"Using existing token to connect to CMS")
                user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            else:
                self.log.warning(f"Regenerating token to connect to CMS")
                status=CMS(cms['ipv4_address']).refresh_token(cms['username'])

                if status=='success':
                    self.log.info(f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                    user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                elif 'error' in status:
                    if 'captcha' in status['error_description']:
                        return 'cms_captcha_error'
                    else:
                        return 'cms_authentication_error'
            self.log.info(f"Querying CMS for applications")
            cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                cms['ipv4_address'])
            cms_applications=CMS(cms['ipv4_address']).applications(cms_services_header)
            app_present = False
            if all([isinstance(db_applications,list), isinstance(cms_applications,list)]):
                self.log.info(
                    f"Applications available in database: {len(db_applications)} and CMS: {len(cms_applications)}")
                allapplication_form=[]
                db_set=set()
                cms_set=set()
                not_in_cuurent_cms = []
                if len(db_applications)>0:
                    for app in db_applications:
                        db_set.add(app['detail']['id'])
                if len(cms_applications)>0:
                    for app in cms_applications:
                        cms_set.add(app['id'])

                cms_diff=cms_set-db_set
                db_diff=db_set-cms_set
                same_app=(cms_set.intersection(db_set))
                if len(cms_diff)>=1:
                    for cms_id in cms_diff:
                        status=CMS(cms['ipv4_address']).application_status(cms_id,cms_services_header)
                        # chnged
                        app={}
                        app['instrumentation']=False
                        app['state']='not_configured'
                        app['message']=''
                        if status:
                            app['instrumentation']=True
                            app['state']='not_configured'
                        else:
                            app['instrumentation']=False
                            app['state']='not_configured'
                            app['message']='Please update the application on CMS'
                        

                        app['config_state']='not_configured'
                        app['homepage_url']=''

                        for i in cms_applications:
                            if i['id']==cms_id:
                                application=dict()
                                app['name']=i['name']
                                app['version']=i['version']
                                app['id']=cms_id
                                
                                application['application_id']=cms_id
                                application['detail']=app
                                application['app_present'] = True
                                
                                allapplication_form.append(application)

                if len(db_diff)>=1:
                    for db_id in db_diff:
                        for data in db_applications:
                            if data['detail']['id']==db_id:
                                if data['detail']['id'] == db_id:
                                    data['app_present'] = False
                                    not_in_cuurent_cms.append(data)

                                        
                if len(same_app)>=1:
                    for app in db_applications:
                        for db_id in same_app:
                            try:
                                if db_id==app['detail']['id']:
                                    app['app_present']= True
                                    if app['detail']['state'] not in ['not_configured','not_instrumented','']:
                                        status=CMS(cms['ipv4_address']).application_status(app['detail']['id'],
                                            cms_services_header)
                                        if not status:
                                            app['detail']['instrumentation']= False
                                            allapplication_form.append(app)
                                        else:
                                            app['detail']['instrumentation']= True
                                            allapplication_form.append(app)


                                    else:
                                        #if db_id == app['detail']['id']:
                                        status=CMS(cms['ipv4_address']).application_status(app['detail']['id'],
                                            cms_services_header)

                                        # chnged
                                        app['detail']['instrumentation']=False
                                        app['detail']['state']='not_configured'
                                        app['detail']['message']=''
                                        if not status:
                                            app['detail']['instrumentation']=False
                                            app['detail']['state']='not_configured'
                                            app['detail']['message']='Please update the application on CMS'
                                       
                                        elif status:
                                            if 'crawl' in app.keys() and 'payload_policy' in app.keys():
                                                if 'attack' in app.keys():
                                                    app['detail']['instrumentation']=True
                                                    app['detail']['state']='report_ready'
                                                    app['detail']['config_state']='configured'

                                                else:
                                                    app['detail']['instrumentation']=True
                                                    app['detail']['state']='attack_ready'
                                                    app['detail']['config_state']='configured'

                                            elif 'payload_policy' in app.keys():
                                                app['detail']['instrumentation']=True
                                                app['detail']['state']='crawl_ready'
                                                app['detail']['config_state']='configured'

                                            else:
                                                app['detail']['instrumentation']=True
                                                app['detail']['state']='not_configured'
                                                app['detail']['config_state']='not_configured'
                                                app['detail']['homepage_url']=''

                                        allapplication_form.append(app)



                            except KeyError:
                                continue

                    import copy
                    db_applications_add=copy.copy(allapplication_form)
                    # for i in db_applications_add:
                    # if '_id' in i:
                    #     i.pop('_id')
                    self.client=MongoClient(host=was.was["database"])
                    self.mydatabase=self.client['was_db']
                    self.application_data=self.mydatabase['applications']
                    self.application_data.delete_many({})
                    self.application_data.insert_many(db_applications_add)
                    if len(not_in_cuurent_cms) > 0:
                        self.application_data.insert_many(not_in_cuurent_cms)
                    for app in allapplication_form:
                        progress=cache_channel.hgetall(app['application_id'])
                        app['detail']['progress']=progress
                    return allapplication_form

                for i in allapplication_form:
                    if '_id' in i.keys():
                        i.pop('_id')
                        
                for i in not_in_cuurent_cms:
                    if '_id' in i.keys():
                        i.pop('_id') 
                        
                self.log.info(f"Updating delta applications in database")
                coll=self.mongo.create_collection(db,'applications')
                self.client=MongoClient(host=was.was["database"])
                self.mydatabase=self.client['was_db']
                self.application_data=self.mydatabase['applications']
                self.application_data.delete_many({})
                status=self.mongo.insert_documents(coll,allapplication_form)
                if len(not_in_cuurent_cms) > 0:
                    status=self.mongo.insert_documents(coll,not_in_cuurent_cms)
                if status=='insert_success':
                    return allapplication_form
                    #db_applications=self.mongo.find_all_documents(coll)
                    # if isinstance(db_applications,list):
                    #     return db_applications
                    # else:
                    #     return db_applications


            else:
                applications=list()
                for app in cms_applications:
                    status=CMS(cms['ipv4_address']).application_status(app['id'],cms_services_header)
                    # chnged
                    app['instrumentation']=False
                    app['state']='not_configured'
                    app['message']=''
                    
                    #if status is None or status.upper()=='UNKNOWN' or status.upper()=='REGISTERED':
                    if not status:
                        app['instrumentation']=False
                        app['state']='not_configured'
                        app['message']='Please update the application on CMS'
                    elif status:
                        app['instrumentation']=True
                        app['state']='not_configured'
                    app['config_state']='not_configured'
                    app['homepage_url']=''

                    application=dict()
                    application['application_id']=app['id']
                    application['detail']=app
                    application['app_present']= True
                    applications.append(application)

                self.log.info(f"Updating delta applications in database")
                coll=self.mongo.create_collection(db,'applications')
                status=self.mongo.insert_documents(coll,applications)
                if status=='insert_success':
                    db_applications=self.mongo.find_all_documents(coll)
                    if isinstance(db_applications,list):
                        return db_applications
                    else:
                        return db_applications
                else:
                    return status
        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()

    def application_authentication(self,application_id,method='',**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'url_store')
                doc=self.mongo.find_document(coll,{'application_id':application_id})
                if doc!='doc_not_found':
                    if 'authentication' in doc:
                        return_map=dict()
                        return_map['authentication']=doc['authentication']
                        return return_map
                    else:
                        self.log.info(f"Field not found in document")
                        return 'field_not_found'
                else:
                    return doc

            elif method.upper()=='POST':
                user_input=kwargs.get('authentication')

                update_status=set()

                if 'homepage_url' in user_input:
                    self.log.info(f"Updating cache for {application_id} with state of homepage-url")
                    #cache_channel.hset(application_id, 'homepage_url', 'configured')
                    #homepage_url = True
                    self.log.info(f"Updating database for application {application_id}")
                    coll=self.mongo.create_collection(db,'applications')
                    application=self.mongo.find_document(coll,{'application_id':application_id})
                    coll=self.mongo.create_collection(db,'url_store')
                    homepage_status=self.mongo.update_document(coll,{
                        '$set':{'authentication.homepage_url':user_input['homepage_url']}},
                        {'application_id':application_id},upsert=True)
                    update_status.add(homepage_status)
                    self.application_services(application_id,method='GET')

                if 'framework_authentication' in user_input:
                    if str(user_input['framework_authentication']['login']).lower()=='true':
                        self.log.info(f"Framework authentication for application {application_id} is enabled")

                        self.log.info(f"Updating cache for {application_id} with state of framework authentication")
                        #cache_channel.hset(application_id, 'framework_authentication', 'configured')
                        #framework_auth = True
                        encrpted_password,key=util.Authentication().encrypt_password(
                            user_input['framework_authentication']['password'])

                        vault_map=dict()
                        vault_map['application_id']=application_id
                        vault_map['authentication']=dict()
                        vault_map['authentication']['framework_authentication']=dict()
                        vault_map['authentication']['framework_authentication']['username']=\
                            user_input['framework_authentication']['username']
                        vault_map['authentication']['framework_authentication']['password']=encrpted_password
                        vault_map['authentication']['framework_authentication']['key']=key

                        coll=self.mongo.create_collection(db,'vault')
                        vault_status=self.mongo.update_document(coll,{'$set':{
                            'authentication.framework_authentication':vault_map['authentication'][
                                'framework_authentication']}},
                            {'application_id':application_id},upsert=True)

                        user_input['framework_authentication'].pop('password')
                    elif str(user_input['framework_authentication']['login']).lower()=='false':
                        self.log.info(f"Framework authentication for application {application_id} is disabled")
                        self.log.info(f"Updating cache for {application_id} with state of framework authentication")
                        #cache_channel.hset(application_id, 'framework_authentication', 'not_configured')
                        #framework_auth = False

                    coll=self.mongo.create_collection(db,'url_store')
                    fw_auth_status=self.mongo.update_document(coll,{
                        '$set':{'authentication.framework_authentication':user_input['framework_authentication']}},
                        {'application_id':application_id},upsert=True)
                    update_status.add(fw_auth_status)

                #HTTP_stream for ____________________

                if 'application_authentication' in user_input:
                    if str(user_input['application_authentication']['login']).lower()=='true':
                        self.log.info(f"Application authentication for application {application_id} is enabled")
                        application_authentication_details={}
                        application_authentication_details['login']=True
                        application_authentication_details['login_url']=user_input['application_authentication'][
                            'login_url']
                        application_authentication_details['logout_url']=user_input['application_authentication'][
                            'logout_url']
                        application_authentication_details['users']={}
                        #application_auth = True
                        for k,v in user_input['application_authentication']['users'].items():
                            application_authentication_details['users'][k]={}
                            application_authentication_details['users'][k]['user_id']=v['user_id']
                            application_authentication_details['users'][k]['username']=v['username']
                            application_authentication_details['users'][k]['type']=v['type']
                            application_authentication_details['users'][k]['http_stream']=[]
                            for i in v['http_stream']:
                                if i['method']=='POST' and 'requestBody' in i:
                                    application_authentication_details['users'][k]['http_stream'].append(i)

                        self.log.info(f"Updating cache for {application_id} with state of application authentication")
                        #cache_channel.hset(application_id, 'application_authentication', 'configured')
                        coll=self.mongo.create_collection(db,'url_store')
                        app_auth_status=self.mongo.update_document(coll,{'$set':{
                            'authentication.application_authentication':application_authentication_details}},
                            {'application_id':application_id},upsert=True)
                        update_status.add(app_auth_status)

                    if str(user_input['application_authentication']['login']).lower()=='false':
                        application_authentication_details={}
                        application_authentication_details['login']=False
                        self.log.info(f"Application authentication for application {application_id} is disabled")
                        self.log.info(f"Updating cache for {application_id} with state of application authentication")
                        #cache_channel.hset(application_id, 'application_authentication', 'not_configured')
                        #application_auth = False
                        # coll=self.mongo.create_collection(db,'url_store')
                        # app_auth_status=self.mongo.update_document(coll,{'$set':{
                        #     'authentication.application_authentication':user_input['application_authentication']}},
                        #     {'application_id':application_id},upsert=True)
                        # update_status.add(app_auth_status)
                        coll=self.mongo.create_collection(db,'url_store')
                        app_auth_status=self.mongo.update_document(coll,{'$set':{
                            'authentication.application_authentication.login':application_authentication_details['login']}},
                            {'application_id':application_id},upsert=True)
                        update_status.add(app_auth_status)

                coll=self.mongo.create_collection(db,'applications')
                application=self.mongo.find_document(coll,{'application_id':application_id})
                #if application['detail']['instrumentation'] is True:
                if str(user_input['application_authentication']['login']).lower()=='true':
                    coll=self.mongo.create_collection(db,'applications')
                    coll_url=self.mongo.create_collection(db,'url_store')
                    application_data=self.mongo.find_document(coll_url,{'application_id':application_id})
                    if 'application_authentication' in application_data['authentication'].keys():
                        doc=self.mongo.update_document(coll,{'$set':{'detail.config_state':'configured',
                            'detail.state':'crawl_ready',
                            'detail.homepage_url':user_input[
                                'homepage_url']}},
                            {'application_id':application_id},upsert=True)
                        self.log.info(f"Application update status: {doc}")
                        cache_channel.hset(application_id,'homepage_url','configured')
                        cache_channel.hset(application_id,'application_authentication','configured')
                        cache_channel.hset(application_id,'framework_authentication','configured')

                    else:
                        doc=self.mongo.update_document(coll,{'$set':{'detail.config_state':'not_configured',
                            'detail.state':'not_configured',
                            'detail.homepage_url':user_input[
                                'homepage_url']}},
                            {'application_id':application_id},upsert=True)
                        self.log.info(f"Application update status: {doc}")
                        cache_channel.hset(application_id,'application_authentication','not_configured')
                        cache_channel.hset(application_id,'framework_authentication','not_configured')
                        cache_channel.hset(application_id,'homepage_url','not_configured')
                else:
                    doc=self.mongo.update_document(coll,{'$set':{'detail.config_state':'configured',
                        'detail.state':'crawl_ready',
                        'detail.homepage_url':user_input[
                            'homepage_url']}},
                        {'application_id':application_id},upsert=True)
                    self.log.info(f"Application update status: {doc}")
                    cache_channel.hset(application_id,'homepage_url','configured')
                    cache_channel.hset(application_id,'application_authentication','configured')
                    cache_channel.hset(application_id,'framework_authentication','configured')

                #elif application['detail']['instrumentation'] is False:
                # doc=self.mongo.update_document(coll,{'$set':{'detail.config_state':'configured',
                #     'detail.state':'',
                #     'detail.homepage_url':user_input[
                #         'homepage_url']}},
                #     {'application_id':application_id},upsert=True)
                # self.log.info(f"Application update status: {doc}")
                # cache_channel.hset(application_id,'application_authentication','configured')
                # cache_channel.hset(application_id,'framework_authentication','configured')
                # cache_channel.hset(application_id,'homepage_url','configured')
                # if 'application_authentication' in user_input:
                #     if str(user_input['application_authentication']['login']).lower() == 'true':
                #         self.log.info(f"Application authentication for application {application_id} is enabled")

                #         self.log.info(f"Updating cache for {application_id} with state of application authentication")
                #         cache_channel.hset(application_id, 'application_authentication', 'configured')

                #     if str(user_input['application_authentication']['login']).lower() == 'false':
                #         self.log.info(f"Application authentication for application {application_id} is disabled")

                #         self.log.info(f"Updating cache for {application_id} with state of application authentication")
                #         cache_channel.hset(application_id, 'application_authentication', 'not_configured')

                #     coll = self.mongo.create_collection(db, 'url_store')
                #     app_auth_status = self.mongo.update_document(coll, {'$set': {
                #         'authentication.application_authentication': user_input['application_authentication']}},
                #                                                  {'application_id': application_id}, upsert=True)
                #     update_status.add(app_auth_status)
                # if all(homepage_url,application_auth,framework_auth) == True:
                # cache_channel.hset(application_id, 'homepage_url', 'configured')
                # cache_channel.hset(application_id, 'application_authentication', 'configured')
                # cache_channel.hset(application_id, 'framework_authentication', 'configured')

                # elif not all(homepage_url,application_auth,framework_auth):
                # cache_channel.hset(application_id, 'application_authentication', 'not_configured')
                # cache_channel.hset(application_id, 'framework_authentication', 'not_configured')
                # cache_channel.hset(application_id, 'homepage_url', 'not_configured')

                if len(update_status)==1:
                    status=[i for i in update_status if len(update_status)==1]
                    self.log.info(f"URL store for application {application_id} updated successfully: {update_status}")
                    return status[0]
                else:
                    self.log.critical(
                        f"URL store for application {application_id} could not update successfully: {update_status}")
                    return 'update_failure'
        finally:
            if db_channel:
                db_channel.close()

    def application_authentication_user(self,method,application_id,user_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method=='POST':
                self.log.info(f"Checking users with URL stores")

                self.log.info(f"Validating configured users for application {application_id}")

                self.log.info(f"Validating users who has performed crawl operation")
                coll=self.mongo.create_collection(db,'applications')
                crawled_users=self.mongo.find_document(coll,{'application_id':application_id},{'crawl.users':1})

                if 'crawl' in crawled_users and len(crawled_users['crawl']['users'])>=1:
                    for user in crawled_users['crawl']['users']:
                        for k,v in user.items():
                            if user_id==v:
                                self.log.info(f"User {user_id} already has URL store generated")
                                return 'url_store_available'
                else:
                    return 'url_store_not_available'


            elif method=='DELETE':
                db_states=set()
                db_channel=self.mongo.connect(host=was.was['database'])

                cache_channel=self.redis.connect(host=was.was['cache'])
                self.log.info(f"Deleting user {user_id} from application {application_id}")
                coll=self.mongo.create_collection(db,'url_store')
                status=self.mongo.update_document(coll,{
                    '$unset':{f'authentication.application_authentication.users.{user_id}':user_id}},
                    {'application_id':application_id},upsert=True)
                db_states.add(status)

                status=self.mongo.update_document(coll,{"$unset":{f'urls.{user_id}':""}},
                    {'application_id':application_id},upsert=True)
                db_states.add(status)

                coll=self.mongo.create_collection(db,'applications')
                self.log.info(f"Checking if user {user_id} has crawled application {application_id}")
                crawl_users=self.mongo.find_document(coll,{'application_id':application_id},{'crawl.users':1})
                if 'crawl' in crawl_users:
                    for app_user in crawl_users['crawl']['users']:
                        if app_user['user_id']==user_id:
                            self.log.info(f"Deleting user {user_id} from Crawl operation")
                            status=self.mongo.update_document(coll,{'$pull':{'crawl.users':{'user_id':user_id}}},
                                {'application_id':application_id})
                            db_states.add(status)

                self.log.info(f"Checking if user {user_id} has attacked application {application_id}")
                attack_users=self.mongo.find_document(coll,{'application_id':application_id},{'attack.users':1})
                if 'attack' in attack_users:
                    # for app_user in attack_users['attack']['users']:
                    #     if app_user['user_id'] == user_id:
                    #         self.log.info(f"Deleting user {user_id} from Attack operation")
                    #         status = self.mongo.update_document(coll, {'$pull': {'attack.users': {'user_id': user_id}}},
                    #                                             {'application_id': application_id})
                    #         db_states.add(status)
                    for k,v in attack_users['attack']['users'].items():
                        if k==user_id:
                            self.log.info(f"Deleting user {user_id} from Attack operation")
                            status=self.mongo.update_document(coll,{'$unset':{f'attack.users.{user_id}':""}},
                                {'application_id':application_id},upsert=True)
                            db_states.add(status)
                coll=self.mongo.create_collection(db,'applications')
                state_change_check=self.mongo.find_document(coll,{'application_id':application_id})
                if "attack" in state_change_check.keys():
                    if len(state_change_check['attack']['users'])>=1:
                        self.mongo.update_document(coll,{'$set':{'detail.state':"report_ready"}},
                            {'application_id':application_id},upsert=True)
                    else:
                        if 'crawl' in state_change_check.keys():
                            if len(state_change_check['crawl']['users'])>=1:
                                self.mongo.update_document(coll,{'$set':{'detail.state':"attack_ready"}},
                                    {'application_id':application_id},upsert=True)
                            else:
                                status=self.mongo.update_document(coll,{'$set':{'detail.state':"crawl_ready"}},
                                    {'application_id':application_id},upsert=True)

                                status=self.mongo.update_document(coll,
                                    {'$set':{'crawl.crawl_state':"not_instantiated"}},
                                    {'application_id':application_id},upsert=True)
                                status=self.mongo.update_document(coll,
                                    {'$set':{'attack.attack_state':"not_instantiated"}},
                                    {'application_id':application_id},upsert=True)
                                status=self.mongo.update_document(coll,{'$unset':{f'detail.url_store':1}},
                                    {'application_id':application_id},upsert=True)
                                cache_channel.hdel('attack',application_id)

                if 'crawl' in state_change_check.keys():
                    if len(state_change_check['crawl']['users'])>=1:
                        self.mongo.update_document(coll,{'$set':{'detail.state':"attack_ready"}},
                            {'application_id':application_id},upsert=True)
                    else:
                        status=self.mongo.update_document(coll,{'$set':{'detail.state':"crawl_ready"}},
                            {'application_id':application_id},upsert=True)
                        status=self.mongo.update_document(coll,{'$set':{'crawl.crawl_state':"not_instantiated"}},
                            {'application_id':application_id},upsert=True)

                        status=self.mongo.update_document(coll,{'$unset':{f'detail.url_store':1}},
                            {'application_id':application_id},upsert=True)

                db_state=[i for i in db_states]
                if db_state[0]=='update_success':
                    self.log.info(f"User {user_id} successfully deleted from application authentication")
                    return 'user_delete_success'
                else:
                    return db_state
        finally:
            if db_channel:
                db_channel.close()

    def application_authentication_test(self,application_id,**kwargs):
        user_input=kwargs.get('authentication')

        if user_input['framework_authentication']['type'].upper()=='NTLMV1' or user_input['framework_authentication'][
            'type'].upper()=='NTLMV2':
            self.log.info(f"Initiating NTLM validation for application: {application_id}")
            response=util.Connect().Windows(user_input['framework_authentication']['host']).ntlm(
                user_input['framework_authentication']['username'],
                user_input['framework_authentication']['password'],
                user_input['framework_authentication']['domain'])
            return response
        elif user_input['framework_authentication']['type'].upper()=='BASIC':
            self.log.info(f"Initiating BASIC validation for application {application_id}")
            if 'http' not in user_input['framework_authentication']['host']:
                host=f"https://{user_input['framework_authentication']['host']}"
            else:
                host=user_input['framework_authentication']['host']
            token=util.Authentication().http_basic_authentication(user_input['framework_authentication']['username'],
                user_input['framework_authentication']['password'])
            header=util.Authentication().create_http_header('basic',token,host)
            response=util.Connect().HTTP(host,header).get()
            if response=='success':
                return 'basic_authentication_success'
            elif response=='failure':
                return 'basic_authentication_failure'
            else:
                return response
        elif user_input['framework_authentication']['type'].upper()=='DIGEST':
            self.log.info(f"Initiating DIGEST validation for application {application_id}")
            if 'http' not in user_input['framework_authentication']['host']:
                host=f"https://{user_input['framework_authentication']['host']}"
            else:
                host=user_input['framework_authentication']['host']
            token=util.Authentication().http_digest_authentication(user_input['framework_authentication']['username'],
                user_input['framework_authentication']['password'])
            header=util.Authentication().create_http_header('digest',token,host)
            response=util.Connect().HTTP(host,header).get()
            if response=='success':
                return 'digest_authentication_success'
            elif response=='failure':
                return 'digest_authentication_failure'
            else:
                return response

    def application_authentication_automated(self,application_id,user_id,**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            user_input=kwargs.get('authentication')
            self.log.info(f"Uploading binary for automated authentication for application: {application_id}")
            if user_input:
                self.log.info(f"File uploaded: {user_input.filename} ({user_input.content_type}) by user {user_id}")
                if user_input.content_type in was.was['supported_content_types']['exe']:
                    db_map=dict()
                    db_map['filename']=user_input.filename
                    db_map['filetype']=user_input.content_type

                    coll=self.mongo.create_collection(db,'url_store')
                    status=self.mongo.update_document(coll,{'$set':{
                        f'authentication.application_authentication.users.{user_id}.filename':user_input.filename,
                        f'authentication.application_authentication.users.{user_id}.filetype':user_input.content_type}},
                        {'application_id':application_id},upsert=True)
                    if status=='update_success':
                        self.log.info(f"Database updated successfully")

                        return_map=dict()
                        return_map['filename']=user_input.filename
                        # return_map['user_id'] = user_id
                        return return_map
                    else:
                        self.log.critical(f"Database could not update successfully")
                        return status
                else:
                    return 'file_not_supported'
            else:
                return 'file_not_found'
        finally:
            if db_channel:
                db_channel.close()

    def application_authentication_automated_test(self,application_id,user_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(
                f"Validating binary for automated authentication for user {user_id} in application: {application_id}")
            return 'success'
        finally:
            if db_channel:
                db_channel.close()

    # def application_authentication_interactive(self, method, application_id, user_id, **kwargs):
    #     try:
    #         db_channel = self.mongo.connect(host=was.was['database'])
    #         db = self.mongo.create_database(db_channel, 'was_db')

    #         if method == 'GET':
    #             authentication_file_path = f"{env.workspace}/artefacts/binaries/authentication.zip"
    #             return authentication_file_path
    #         elif method == 'POST':
    #             user_input = kwargs.get('authentication')

    #             if isinstance(user_input['http_stream'], list):
    #                 coll = self.mongo.create_collection(db, 'applications')
    #                 application = self.mongo.find_document(coll, {'application_id': application_id})

    #                 url_store_coll = self.mongo.create_collection(db, 'url_store')
    #                 status = self.mongo.update_document(url_store_coll, {
    #                     '$set': {f'authentication.application_authentication.users.{user_id}.state': 'authenticated',
    #                              f'authentication.application_authentication.users.{user_id}.http_stream': user_input[
    #                                  'http_stream']}},
    #                                                     {'application_id': application_id}, upsert=True)
    #                 if status == 'update_success':
    #                     self.log.info(
    #                         f"HTTP stream for user {user_id} is successfully saved for application- {application_id}")
    #                     try:
    #                         subject = f"Interactive authentication successful"
    #                         message = f"Interactive authentication successfully completed for application {application['detail']['name']} ({application_id})"
    #                         util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
    #                                                   message=message, application_id=application_id,
    #                                                   application_name=application['detail']['name'])
    #                         util.Notification().smtp(subject=subject, message=message)
    #                         self.log.info(message, notify=True)
    #                         #
    #                         # return 'authentication_success'
    #                         return 'interactive_authentication_update_success'

    #                     except Exception :
    #                         pass

    #             elif user_input['event'] == 'no':
    #                 return 'authentication_unsuccess'
    #     finally:
    #         if db_channel:
    #             db_channel.close()

    def application_authentication_interactive_test(self,application_id,user_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            self.log.info(f"Validating interactive authentication for {user_id} in application {application_id}")
            session=''
            return 'success',session
        finally:
            if db_channel:
                db_channel.close()

    def application_services(self,application_id,method='',**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            cache_channel=self.redis.connect(host=was.was['cache'])

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'url_store')
                transaction_doc=self.mongo.find_document(coll,{'application_id':application_id},{'services':True})
                if 'services' in transaction_doc:
                    return_map=dict()
                    return_map['services']=transaction_doc['services']
                    return return_map

                self.log.info(f"Checking token expiry status")
                if cache_channel.exists('cms'):
                    cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                else:
                    self.log.critical(f"CMS is not configured to fetch applications")
                    return 'cms_not_configured'
                self.log.warning(f"CMS token will expire in {cache_channel.ttl(cms['username'])} seconds")
                if cache_channel.ttl(cms['username'])>300:
                    self.log.info(f"Using existing token to connect to CMS")
                    user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                else:
                    self.log.warning(f"Regenerating token to connect to CMS")
                    status=CMS(cms['ipv4_address']).refresh_token(cms['username'])
                    if status=='success':
                        self.log.info(f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                        user=util.ConvertData(
                            (cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()

                self.log.info(f"Querying CMS for applications instances & services")
                cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                    cms['ipv4_address'])
                cms_application_services=CMS(cms['ipv4_address']).application_services(application_id,
                    cms_services_header)

                services=dict()
                for service in cms_application_services:
                    services[service['serviceTag']]=dict()
                    services[service['serviceTag']]['name']=service['name']
                    services[service['serviceTag']]['tag']=service['serviceTag']
                    services[service['serviceTag']]['instances']=service['applicationInstances']
                    services[service['serviceTag']]['urls']=dict()

                app_map=dict()
                app_map['application_id']=application_id
                app_map['services']=services

                coll=self.mongo.create_collection(db,'url_store')
                status=self.mongo.update_document(coll,{'$set':{'services':services}},
                    {'application_id':application_id},upsert=True)
                if status=='update_success':
                    return_map=dict()
                    return_map['services']=services
                    return return_map
                else:
                    return status

            elif method.upper()=='POST':
                user_input=kwargs.get('services')

                db_update=dict()
                for k,v in user_input.items():
                    db_update[f"services.{k}.urls"]=v['urls']

                coll=self.mongo.create_collection(db,'url_store')
                status=self.mongo.update_document(coll,{'$set':db_update},{'application_id':application_id})
                if status=='update_success':
                    self.log.info(f'Service URIs update successful')
                    return 'services_update_success'
                else:
                    self.log.info(f'Service URIs update unsuccessful')
                    return status
        finally:
            if db_channel:
                db_channel.close()

    def application_pre_crawl(self,application_id,method='',**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'pre_crawl_store')
                burp_xml_doc=self.mongo.find_document(coll,{'application_id':application_id},
                    {'burp_xml.files':1,'burp_xml.generated':1})
                manual_doc=self.mongo.find_document(coll,{'application_id':application_id},{'manual':1})

                return_map=dict()
                if 'burp_xml' in burp_xml_doc:
                    self.log.info(f"Files used to generate pre-crawl store: {burp_xml_doc['burp_xml']['files']}")
                    state=cache_channel.hget(application_id,'burp_xml_pre_crawl').decode('utf-8')

                    return_map['burp_xml']=dict()
                    return_map['burp_xml']['files']=burp_xml_doc['burp_xml']['files']
                    return_map['burp_xml']['state']=state
                    return_map['burp_xml']['generated']=burp_xml_doc['burp_xml']['generated']
                if 'manual' in manual_doc:
                    state=cache_channel.hget(application_id,'manual_pre_crawl').decode('utf-8')

                    return_map['manual']=manual_doc['manual']
                    return_map['manual']['state']=state
                return return_map

            elif method.upper()=='POST':
                self.log.info(f"Initiating pre-crawl for application: {application_id}")
                user_input=kwargs.get('pre_crawl')

                if user_input['store_type']=='burp_xml':
                    if user_input['file']:
                        self.log.info(
                            f"File uploaded: {user_input['file'].filename} of type {user_input['file'].content_type}")
                        crawl_map=dict()
                        crawl_map[user_input['store_type']]=dict()
                        crawl_map[user_input['store_type']]['files']=list()
                        crawl_map[user_input['store_type']]['urls']=list()

                        if user_input['file'].content_type in was.was['supported_content_types']['xml']:
                            self.log.info(f"Updating cache for {application_id} with state of burp-xml pre-crawl")
                            cache_channel.hset(application_id,'burp_xml_pre_crawl','in_progress')

                            self.log.info(
                                f"Parsing {user_input['file'].content_type} with filename {user_input['file'].filename} for store-type: {user_input['store_type']}")
                            files=dict()
                            files['file_name']=user_input['file'].filename
                            files['file_type']=user_input['file'].content_type
                            files['size']=util.ConvertData(user_input['file']).file_size()
                            files['upload_time']=datetime.now()
                            # files['store_type'] = user_input['store_type']

                            crawl_map[user_input['store_type']]['files'].append(files)
                            data=util.ConvertData(user_input['file']).xml_root()

                            count=1
                            for item in data.findall('item'):
                                lines=item.find('url').text.splitlines()
                                pre_crawl=dict()
                                pre_crawl[f"url_{count}"]=dict()
                                if item.find('method').text=='POST':
                                    pre_crawl[f"url_{count}"]['url_id']=f"url_{count}"
                                    pre_crawl[f"url_{count}"]['attack_url']=lines[0].split('?')[0]
                                    pre_crawl[f"url_{count}"]['request_type']=item.find('method').text
                                    pre_crawl[f"url_{count}"]['user_agent']=[line.split(':')[0].strip() for line in
                                        lines if 'user-agent' in line.lower()]
                                    pre_crawl[f"url_{count}"]['parameters']=dict()
                                    pre_crawl[f"url_{count}"]['exercisable_parameters']=[]
                                    parsed=urlparse.urlparse(lines[0])
                                    query_obj=parse_qs(parsed.query,keep_blank_values=True)
                                    for d in query_obj:
                                        pre_crawl[f"url_{count}"]['exercisable_parameters'].append(d)
                                        pre_crawl[f"url_{count}"]['parameters']={''.join(d):"".join(query_obj[d])}
                                elif item.find('method').text=='GET':
                                    pre_crawl[f"url_{count}"]['url_id']=f"url_{count}"
                                    pre_crawl[f"url_{count}"]['attack_url']=lines[0].split('?')[0]
                                    pre_crawl[f"url_{count}"]['request_type']=item.find('method').text
                                    pre_crawl[f"url_{count}"]['user_agent']=[line.split(':')[0].strip() for line in
                                        lines if 'user-agent' in line.lower()]
                                    pre_crawl[f"url_{count}"]['parameters']=dict()
                                    pre_crawl[f"url_{count}"]['exercisable_parameters']=[]
                                    parsed=urlparse.urlparse(lines[0])
                                    query_obj=parse_qs(parsed.query,keep_blank_values=True)
                                    for d in query_obj:
                                        pre_crawl[f"url_{count}"]['exercisable_parameters'].append(d)
                                        pre_crawl[f"url_{count}"]['parameters']={''.join(d):"".join(query_obj[d])}

                                count+=1
                                crawl_map[user_input['store_type']]['urls'].append(pre_crawl)
                        else:
                            return 'file_not_supported'

                        coll=self.mongo.create_collection(db,'pre_crawl_store')
                        doc=self.mongo.find_document(coll,{'application_id':application_id})
                        if 'error' not in doc:
                            if user_input['store_type'] not in doc:
                                crawl_map[user_input['store_type']]['generated']=datetime.now()
                                status=self.mongo.update_document(coll,{
                                    '$set':{user_input['store_type']:crawl_map[user_input['store_type']]}},
                                    {'application_id':application_id},upsert=True)
                                if status=='update_success':
                                    self.log.info(
                                        f"Updating cache for {application_id} with state of burp-xml pre-crawl")
                                    cache_channel.hset(application_id,'burp_xml_pre_crawl','completed')
                                return status
                            if user_input['store_type'] in doc:
                                self.log.info(f"URLs de-duplication in progress...")
                                delta_urls=list(
                                    itertools.filterfalse(lambda x:x in doc[user_input['store_type']]['urls'],
                                        crawl_map[user_input['store_type']]['urls']))+list(
                                    itertools.filterfalse(lambda x:x in crawl_map[user_input['store_type']]['urls'],
                                        doc[user_input['store_type']]['urls']))
                                # delta_urls = set(doc[user_input['store_type']]['urls']).symmetric_difference(
                                #     set(crawl_map[user_input['store_type']]['urls']))

                                # for i in [p for p in doc[user_input[store_type]][urls]]:
                                # for i in [p for p in doc[user_input['store_type']]['urls']]:
                                #     for j in [k for k in crawl_map[user_input['store_type']]['urls']]:
                                # for i in doc[user_input[store_type]][urls]:
                                #     for j in crawl_map[user_input['store_type']]['urls']:
                                for (i,j) in itertools.zip_longest(doc[user_input['store_type']]['urls'],
                                        crawl_map[user_input['store_type']]['urls']):
                                    for k,v in i.items():
                                        for k1,v1 in j.items():
                                            if v['attack_url']==v1['attack_url']:
                                                delta_parameter=list(
                                                    itertools.filterfalse(lambda x:x in v['parameters'],
                                                        v1['parameters']))+list(
                                                    itertools.filterfalse(lambda x:x in v1['parameters'],
                                                        v['parameters']))
                                                # delta_parameter = set(doc[user_input['store_type']]['urls'][i][
                                                #                       'parameters']).symmetric_difference(
                                                # crawl_map[user_input['store_type']]['urls'][i]['parameters'])
                                                if delta_parameter:
                                                    self.log.info(f"URL {i} has delta parameters: {delta_parameter}")
                                                    delta_urls.add(j)
                                self.log.info(f"There are {len(delta_urls)} delta URLs")
                                db_map=list()
                                for url in delta_urls:
                                    db_map.append(crawl_map[user_input['store_type']]['urls'][url])
                                if db_map:
                                    crawl_map[user_input['store_type']]['updated']=datetime.now()
                                    status=self.mongo.update_documents(coll,{
                                        '$set':{f"{user_input['store_type']}.urls":db_map}},
                                        {'application_id':application_id})
                                    if status=='update_success':
                                        self.log.info(f"Pre-crawl URL store generated successfully")

                                        self.log.info(
                                            f"Updating cache for {application_id} with state of burp-xml pre-crawl")
                                        cache_channel.hset(application_id,'burp_xml_pre_crawl','completed')
                                    return status
                                else:
                                    self.log.info(
                                        f"Updating cache for {application_id} with state of burp-xml pre-crawl")
                                    cache_channel.hset(application_id,'burp_xml_pre_crawl','completed')
                                    return 'updates_not_available'

                    else:
                        return 'file_not_found'
                elif user_input['store_type']=='manual':
                    if not user_input['state']:
                        coll=self.mongo.create_collection(db,'applications')
                        app_doc=self.mongo.find_document(coll,{'application_id':application_id})
                        if isinstance(app_doc,dict):
                            self.log.info(
                                f"Homepage URL of application {application_id}: {app_doc['detail']['homepage_url']}")
                            return_map=dict()
                            return_map['pre_crawl']=dict()
                            return_map['pre_crawl'][user_input['store_type']]=dict()
                            # return_map['pre_crawl'][user_input['store_type']][
                            #     'ipv4_address'] = util.Network().get_ipv4()
                            return_map['pre_crawl'][user_input['store_type']][
                                'ipv4_address']=was.was["host_ip"]
                            # return_map['pre_crawl'][user_input['store_type']]['port'] = util.Network().get_port_number()
                            return_map['pre_crawl'][user_input['store_type']]['port']=8080

                            coll=self.mongo.create_collection(db,'pre_crawl_store')
                            app_doc=self.mongo.update_document(coll,{'$set':{
                                'manual.ipv4_address':return_map['pre_crawl'][user_input['store_type']][
                                    'ipv4_address'],
                                'manual.port':return_map['pre_crawl'][user_input['store_type']]['port']}},
                                {'application_id':application_id},
                                upsert=True)
                            if app_doc=='update_success':
                                return return_map
                    if user_input['state']=='terminate':
                        def pre_crawl_response():
                            self.log.info(f"Updating cache for {application_id} with state of manual pre-crawl")
                            cache_channel.hset(application_id,'manual_pre_crawl','terminated')

                            return 'terminate_success'

                        def pre_crawl_i():
                            # time.sleep(10)
                            self.log.info(f"Updating cache for {application_id} with state of manual pre-crawl")
                            cache_channel.hset(application_id,'manual_pre_crawl','in_progress')

                            crawl_map=dict()
                            crawl_map[user_input['store_type']]=dict()
                            crawl_map[user_input['store_type']]['generated']=datetime.now()
                            crawl_map[user_input['store_type']]['urls']=dict()

                            # time.sleep(10)

                            coll=self.mongo.create_collection(db,'pre_crawl_store')
                            status=self.mongo.update_document(coll,{
                                '$set':{'manual.generated':crawl_map[user_input['store_type']]['generated'],
                                    'manual.urls':crawl_map[user_input['store_type']]['urls']}},
                                {'application_id':application_id},upsert=True)
                            cops.Crawl(application_id).application_pre_crawl()
                            if status=='update_success':
                                self.log.info(f"Manual pre-crawl is completed for {application_id}")

                                self.log.info(f"Updating cache for {application_id} with state of manual pre-crawl")
                                cache_channel.hset(application_id,'manual_pre_crawl','completed')

                            # # ----- Notify Start-----
                            # TODO: SMTP changes
                            ###########################################
                            app_coll=self.mongo.create_collection(db,'applications')
                            application=self.mongo.find_document(app_coll,{'application_id':application_id})
                            self.mongo.update_document(app_coll,{'$set':{'detail.state':"crawl_ready"}},
                                                       {'application_id':application_id},upsert=True)
                            subject=f"Manual pre-crawl completed"
                            message=f"Manual pre-crawl successfully completed for application {application['detail']['name']} ({application_id})"
                            util.Notification().flash(timestamp=time.time(),level='INFO',operation='Pre_Crawl',
                                message=message,application_id=application_id,
                                application_name=application['detail']['name'])
                            util.Notification().smtp(subject=subject,message=message)
                            self.log.info(message,notify=True)
                            ###########################################
                            # # ----- Notify End-----

                        pool=ThreadPool(processes=3)
                        t1=pool.apply_async(pre_crawl_response)
                        t2=pool.apply_async(pre_crawl_i)
                        return t1.get()

                    elif user_input['state']=='status':
                        status=cache_channel.hget(application_id,'manual_pre_crawl').decode('utf-8')
                        return status
                    elif user_input['state']=='instantiate':
                        self.log.info(f"Updating cache for {application_id} with state of pre-crawl")
                        if cops.Crawl(application_id).start_mitm():
                            cache_channel.hset(application_id,'manual_pre_crawl','instantiated')
                            #cache_channel.hset(application_id, 'manual_pre_crawl', 'terminated')
                            #return 'terminate_success'
                            return 'manual_instantiated'

            elif method.upper()=='PUT':
                self.log.info(f"Updating pre-crawl for application: {application_id}")
                #app_coll=self.mongo.create_collection(db,'applications')
                #application=self.mongo.find_document(app_coll,{'application_id':application_id})

                user_input=kwargs.get('pre_crawl')
                URL_status=True
                status_record=set()
                for v in user_input.get('urls',{}).values():
                    url_parse=urllib.parse.urlparse(v.get('attack_url',""))
                    if not all([url_parse.scheme,url_parse.netloc]):
                        URL_status=False

                # h=application['detail']['homepage_url']
                # parsed_url=urllib.parse.urlparse(h)
                # hostname=parsed_url.netloc
                # user_input=kwargs.get('pre_crawl')
                # URL_status=True
                # status_record=set()
                # for k,v in user_input['urls'].items():
                #     if hostname not in v['attack_url']:
                #         URL_status=False

                if URL_status==True:
                    coll=self.mongo.create_collection(db,'pre_crawl_store')

                    for url in user_input['urls']:
                        status=self.mongo.update_document(coll,{
                            '$set':{f"manual.urls.{url}":user_input['urls'][url]}},
                            {'application_id':application_id})
                        status_record.add(status)

                return list(status_record)


        finally:
            if db_channel:
                db_channel.close()

    def application_pre_crawl_view(self,application_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            coll=self.mongo.create_collection(db,'pre_crawl_store')
            doc=self.mongo.find_document(coll,{'application_id':application_id})
            if doc!='document_not_found':
                return_map=list()

                if 'burp_xml' in doc:
                    self.log.info(f"Files used to generate pre-crawl store: {doc['burp_xml']['files']}")
                    check=doc['burp_xml']['urls']
                    for i in check:
                        for k,v in i.items():
                            return_map.append(v)

                    return return_map
                elif 'manual' in doc:
                    # self.log.info(f"Files used to generate pre-crawl store: {doc['manual']['files']}")
                    check=list(doc['manual']['urls'].values())
                    for i in check:
                        return_map.append(i)

                    return return_map
            else:
                return doc
        finally:
            if db_channel:
                db_channel.close()

    def application_payload_policy(self,application_id,method='',**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'applications')
                doc=self.mongo.find_document(coll,{'application_id':application_id})
                if doc!='document_not_found':
                    if 'payload_policy' in doc:
                        self.log.info(f"Payload policy details for application {application_id} found in database")
                        return doc
                    else:
                        self.log.warning(
                            f"Payload policy details for application {application_id} not found in database")
                        return 'field_not_found'
                else:
                    return doc

            elif method.upper()=='POST':
                user_input=kwargs.get('application')
                coll=self.mongo.create_collection(db,'applications')
                # doc = self.mongo.find_document(coll, {'application_id': application_id})
                # if doc == 'document_not_found':
                #     self.log.info(f"Inserting payload policy details for application {application_id}")
                #     app_map = dict()
                #     app_map['application_id'] = application_id
                #     app_map['payload_policy'] = user_input['payload_policy']
                #     status = self.mongo.insert_document(coll, app_map)
                #     return status
                # elif doc != 'document_not_found':
                self.log.info(f"Updating payload policy details for application {application_id}")
                status=self.mongo.update_document(coll,{'$set':user_input},{'application_id':application_id},
                    upsert=True)
                if status=='update_success':
                    self.log.info(f"Updating cache for {application_id} with state of payload policy")
                    cache_channel.hset(application_id,'payload_policy','configured')
                # self.application_services(application_id,method='GET')
                return status
        finally:
            if db_channel:
                db_channel.close()

    def application_transactions(self,application_id,transaction_id='',url_id='',method='',**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'transaction_store')
                doc=self.mongo.find_document(coll,{'application_id':application_id})
                if doc!='document_not_found':
                    if 'transactions' in doc:
                        return doc
                    else:
                        return 'field_not_found'
                else:
                    self.log.warning(f"Document for application {application_id} not found in database")
                    return doc

            elif method.upper()=='POST':
                user_input=kwargs.get('transaction')
                if user_input:
                    self.log.info(f"File uploaded: {user_input.filename} of type {user_input.content_type}")
                    if user_input.content_type in was.was['supported_content_types']['exe']:
                        dummy_data=dummy.transactions
                        coll=self.mongo.create_collection(db,'transaction_store')
                        self.log.info(f"Updating transaction details for application {application_id}")
                        status=self.mongo.update_document(coll,{'$set':dummy_data},
                            {'application_id':application_id},upsert=True)
                        if status=='update_success':
                            self.log.info(f"Updating cache for {application_id} with state of transaction store")
                            cache_channel.hset(application_id,'transaction_store','configured')

                            self.log.info(f"Updating transaction details for application {application_id}")

                            coll=self.mongo.create_collection(db,'applications')
                            application=self.mongo.find_document(coll,{'application_id':application_id})

                            if application['detail']['instrumentation'] is True:
                                status=self.mongo.update_document(coll,{'$set':{'detail.state':'attack_ready',
                                    'detail.transaction_store':'generated'}},
                                    {'application_id':application_id},upsert=True)
                            elif application['detail']['instrumentation'] is False:
                                status=self.mongo.update_document(coll,{'$set':{'detail.state':'not_instrumented',
                                    'detail.transaction_store':'generated'}},
                                    {'application_id':application_id},upsert=True)
                            if status=='update_success':
                                self.log.info(f"Transaction store is successfully updated")
                                return 'transaction_store_update_success'
                            else:
                                return status
                        else:
                            return status
                    else:
                        return 'file_not_supported'
                else:
                    return 'file_not_found'

            elif method.upper()=='DELETE':
                coll=self.mongo.create_collection(db,'transaction_store')
                doc=self.mongo.find_document(coll,{'application_id':application_id})
                if doc!='document_not_found':
                    self.log.info(f"Updating transaction details for application {application_id}")

                    if transaction_id:
                        for tk,tv in doc['transactions'].items():
                            if transaction_id in tk:
                                txn_tree=f"transactions.{transaction_id}"
                                if url_id:
                                    for uk,uv in tv['urls'].items():
                                        if url_id in uk:
                                            url_tree=f"transactions.{transaction_id}.urls.{url_id}"
                                    status=self.mongo.update_document(coll,{'$unset':{url_tree:url_id}},
                                        {'application_id':application_id})
                                    return status
                                else:
                                    status=self.mongo.update_document(coll,{'$unset':{txn_tree:transaction_id}},
                                        {'application_id':application_id})
                                    if status=='update_success':
                                        txn_state=self.mongo.find_document(coll,{'application_id':application_id})
                                        if len(txn_state['transactions'])<1:
                                            self.log.info(f"Removing transaction store tag from applications")
                                            coll=self.mongo.create_collection(db,'applications')
                                            self.log.info(
                                                f"Updating transaction details for application {application_id}")
                                            status=self.mongo.update_document(coll,{
                                                '$unset':{'detail.state':'crawl_ready',
                                                    'detail.transaction_store':''}},
                                                {'application_id':application_id},
                                                upsert=True)
                                    return status
                else:
                    return doc
        finally:
            if db_channel:
                db_channel.close()

    def application_transaction_test(self,application_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Validating binary for automated authentication for application: {application_id}")
            return 'success'
        finally:
            if db_channel:
                db_channel.close()

    def crawl(self,application_id='',method='',request_state=None,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'applications')
                if request_state is None:
                    applications=self.mongo.find_all_documents(coll)
                    if isinstance(applications,list):
                        crawl_eligible=list()
                        coll=self.mongo.create_collection(db,'url_store')
                        for app in applications:
                            app_detail=dict()
                            if app.get('app_present',False) == True:
                                
                                if app['detail']['state']=='crawl_ready' or app['detail']['state']=='crawling' or\
                                        app['detail']['state']=='attack_ready' or app['detail']['state']=='attacking' or\
                                        app['detail']['state']=='report_ready' or app['detail']['state']=='aborted' or\
                                        app['detail']['state']=='terminated' or app['detail'][
                                    'state']=='report_generation':
                                    url=self.mongo.find_document(coll,{'application_id':app['detail']['id']})
                                    if url!='document_not_found':
                                        try:
                                            if 'homepage_url' in url['authentication']:
                                                app.pop('_id')
                                                app_detail.update(app['detail'])
                                                if 'crawl' not in app:
                                                    app_detail['crawl']=dict()
                                                    app_detail['crawl']['crawl_state']='not_instantiated'
                                                    app_detail['crawl']['crawl_completed']=0
                                                elif 'crawl' in app:
                                                    if 'crawl_completed' in app['crawl']:
                                                        app_detail['crawl']=app['crawl']
                                                    else:
                                                        app_detail['crawl']=app['crawl']
                                                        app_detail['crawl']['crawl_completed']=0
                                                if 'attack' in app:
                                                    app_detail['attack']=dict()
                                                    app_detail['attack']['attack_state']=app['attack']
                                                
                                                if url['authentication']['application_authentication']['login'] == True:
                                                    if 'users' in url['authentication']['application_authentication']:
                                                        app_detail['users']=dict()
                                                        app_detail['users'].update(
                                                            url['authentication']['application_authentication']['users'])
                                                if app_detail:
                                                    crawl_eligible.append(app_detail)
                                            else:
                                                continue
                                        except Exception:
                                            continue
                        return crawl_eligible
                    elif applications=='documents_not_found':
                        return 'applications_not_found'
                elif request_state=='status':
                    self.log.info(f"Checking crawl state for application {application_id}")
                    doc=self.mongo.find_document(coll,{'application_id':application_id})
                    if doc!='document_not_found':
                        crawl=dict()
                        crawl['crawl_state']=doc['crawl']['crawl_state']
                        if 'crawl_completed' in doc['crawl']:
                            crawl['crawl_completed']=doc['crawl']['crawl_completed']
                        return crawl
                    else:
                        return doc
                elif request_state=='progress':
                    cops.Crawl(application_id).progress()
                elif request_state=='status_progress':
                    user_input=kwargs.get('crawl')

                    if cache_channel.exists('crawl'):
                        crawling_apps=cache_channel.hgetall('crawl')
                        status_progress=list()
                        for k,v in crawling_apps.items():
                            # cache_map['crawl_state'] = crawl_state
                            # cache_map['crawl_progress'] = random.randint(1, 100)
                            # cache_channel.hmset('crawl', {application_id: str(cache_map)})
                            # cops.Crawl(application_id).progress()
                            status_progress.append(util.ConvertData(v.decode('utf-8')).framework_compatible())
                        return status_progress
                    else:
                        self.log.warning(f"Crawl not in progress for any applications")
                        return 'applications_not_available'
                elif request_state=='logs':
                    user_input=kwargs.get('crawl')

                    if user_input['download'] is None:
                        file=f"{env.workspace}/artefacts/traces/crawl.log"
                        with open(file,'r') as fo:
                            if user_input['lines']!='all':
                                content_filter=list()
                                for line in fo.readlines():
                                    if user_input['level']:
                                        if user_input['level'].upper() in line:
                                            content_filter.append(line.strip())
                                    else:
                                        content_filter.append(line.strip())
                                return content_filter[-int(user_input['lines']):]
                            else:
                                content_filter=list()
                                for line in fo.readlines():
                                    content_filter.append(line.strip())
                                return content_filter
                    elif user_input['download'].lower()=='true':
                        log_file_path=f"{env.workspace}/artefacts/traces/crawl.log"
                        return log_file_path

            elif method.upper()=='POST':
                user_input=kwargs.get('crawl')
                coll=self.mongo.create_collection(db,'applications')
                application=self.mongo.find_document(coll,{'application_id':application_id})
                
                if application == 'document_not_found':
                    return 'document_not_found'

                cache_map=dict()
                cache_map['application_id']=application_id

                if request_state=='instantiate' or request_state=='aborted':
                    self.log.info(f"Initiating crawl for application {application_id}")

                    def crawl_response():
                        coll=self.mongo.create_collection(db,'applications')
                        self.mongo.update_document(coll,{'$set':{'detail.state':'crawling'}},
                            {'application_id':application_id},
                            upsert=True)
                        message=f"Crawl operation instantiated for application {application['detail']['name']} ({application_id})"
                        util.Notification().flash(timestamp=time.time(),level='INFO',operation='Crawl',
                            message=message,application_id=application_id,
                            application_name=application['detail']['name'])

                        return 'instantiated'

                    def crawl_i():
                        start_time=time.time()
                        crawl_state='instantiated'
                        coll=self.mongo.create_collection(db,'applications')
                        application=self.mongo.find_document(coll,{'application_id':application_id})
                        # db_users = []
                        end_time=time.time()
                        self.log.info(f"Transitioning crawl state to {crawl_state}")
                        cache_map['crawl_state']=crawl_state
                        cache_channel.hmset('crawl',{application_id:str(cache_map)})

                        db_map=dict()
                        db_map['crawl']=dict()
                        
                        db_map['crawl']['crawl_type']=user_input['crawl']['type']
                        db_map['crawl']['url_store']=user_input['crawl']['url_store']
                        db_map['crawl']['attack']=user_input['crawl']['attack']
                        db_map['crawl']['crawl_state']=crawl_state
                        db_map['crawl']['crawl_instantiated']=end_time
                        if 'crawl' in application.keys():
                            db_map['crawl']['users']=application['crawl']['users']
                        else:
                            db_map['crawl']['users']=list()
                        
                        # if 'users' in user_input['crawl']:
                        #     for k,v in user_input['crawl']['users'].items():
                        #         current_uers_id = v['user_id']
                                
                        # for i in db_map['crawl']['users']:
                        #     db_users.append(i['user_id'])
                            
                        # if 'users' in user_input['crawl']:
                        #     for k,v in user_input['crawl']['users'].items():
                        #         #current_uers_id = v['user_id']
                        #         if len(db_map['crawl']['users'])!= 0:
                        #             if v['user_id'] not in db_users:
                        #                 db_map['crawl']['users'].append(v)
                        #         else:
                        #             db_map['crawl']['users'].append(v)

                        coll=self.mongo.create_collection(db,'applications')
                        if user_input['crawl']['url_store']=='replace':
                            self.mongo.update_document(coll,{'$set':db_map},{'application_id':application_id},
                                upsert=True)
                        elif user_input['crawl']['url_store']=='update':
                            app=self.mongo.find_document(coll,{'application_id':application_id})
                            self.mongo.update_document(coll,{'$set':db_map},{'application_id':application_id},
                                upsert=True)
                            if not 'crawl' in app:
                                self.mongo.update_document(coll,{'$set':db_map},{'application_id':application_id},
                                    upsert=True)
                            else:
                                self.mongo.update_document(coll,{'$set':db_map},{'application_id':application_id},
                                    upsert=True)
                                # self.mongo.update_document(coll, {
                                #     '$addToSet': {'crawl.users': {'$each': [app['crawl']['users'][0]]}}},
                                #                            {'application_id': application_id}, upsert=True)

                        app_coll=self.mongo.create_collection(db,'applications')
                        app_doc=self.mongo.find_document(app_coll,{'application_id':application_id})
                        us_coll=self.mongo.create_collection(db,'url_store')
                        us_doc=self.mongo.find_document(us_coll,{'application_id':application_id})
                        time.sleep(10)

                        crawl_state='in_progress'
                        self.log.info(f"Transitioning crawl state to {crawl_state}")
                        self.mongo.update_document(coll,{'$set':{'crawl.crawl_state':crawl_state}},
                            {'application_id':application_id},upsert=True)
                        cache_map['crawl_state']=crawl_state
                        cache_channel.hmset('crawl',{application_id:str(cache_map)})

                        # for i in range(5):
                        #     import random
                        #     cache_map['crawl_state'] = crawl_state
                        #     cache_map['crawl_progress'] = random.randint(1, 100)
                        #     cache_channel.hmset('crawl', {application_id: str(cache_map)})
                        #     time.sleep(5)

                        cops.Crawl(application_id).initiate(user_input=user_input)

                        app_coll=self.mongo.create_collection(db,'applications')
                        app_doc=self.mongo.find_document(app_coll,{'application_id':application_id})
                        if app_doc['crawl']['attack']==True:
                            self.attack(application_id=application_id,method='POST',request_state='instantiate',
                                kwargs={'attack':'attack'})
                            self.log.info("attack started")

                        # Integration begins here

                        # usersInfo = {"users": {
                        #     "user_0": {"user_id": "user_0", "username": "anonymous", "type": "interactive",
                        #                "reuse_credentials": "true"}}}
                        # appId = "5fad1250b1620e1ff50ec387"
                        # appName = "BookStore"
                        # appURL = "http://10.20.7.90:8080/bookstore/Default.jsp"
                        # crawlType = "manual"

                        # crawler = Crawler(applicationId=application_id, applicationName=app_doc['detail']['name'],
                        #                   applicationURL=us_doc['authentication']['homepage_url'],
                        #                   crawlType=user_input['type'], usersInfo=user_input['users']).crawlProcess()

                        # Integration ends here

                        # time.sleep(10)
                        # crawl_state = 'completed'
                        # end_time = time.time()
                        # self.log.info(f"Transitioning crawl state to {crawl_state}")
                        # cache_map['crawl_state'] = crawl_state
                        # cache_channel.hmset('crawl', {application_id: str(cache_map)})

                        # app_status = self.mongo.update_document(coll, {
                        #     '$set': {'detail.state': 'attack_ready','detail.url_store':'genarate', 'crawl.crawl_state': crawl_state,
                        #              'crawl.crawl_completed': end_time}},
                        #                                         {'application_id': application_id}, upsert=True)
                        # if app_status == 'update_success':
                        #     subject = f"Crawl operation completed"
                        #     message = f"Crawl operation completed for application {application['detail']['name']} ({application_id})"
                        #     # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                        #     #                           message=message, application_id=application_id,
                        #     #                           application_name=application['detail']['name'])
                        #     # util.Notification().smtp(subject=subject, message=message)
                        #     self.log.info(message, notify=True)
                        # time.sleep(10)
                        # cache_channel.hdel('crawl', application_id)
                        # app_coll = self.mongo.create_collection(db, 'applications')
                        # app_doc = self.mongo.find_document(app_coll, {'application_id': application_id})
                        # if app_doc['crawl']['attack'] == True:
                        #     self.attack(application_id=application_id, method='POST', request_state='instantiate',
                        #                 kwargs={'attack': 'attack'})
                        #     self.log.info("attack started")

                    #
                    #     urls = dict()
                    #     urls['urls'] = dict()
                    #     for i in range(10):
                    #         url = {
                    #             f"url_{i}": {
                    #                 "attack_url": f"/benchmark/{i}",
                    #                 "exercisable_parameters": [f"test{i}_a", f"test{i}_b"],
                    #                 "parameters": {},
                    #                 "request_type": "POST",
                    #                 "url_id": f"url_{i}",
                    #                 "user_agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv"
                    #             }
                    #         }
                    #         urls['urls'].update(url)
                    #
                    #     coll = self.mongo.create_collection(db, 'url_store')
                    #     status = self.mongo.update_document(coll, {'$set': urls}, {'application_id': application_id},
                    #                                         upsert=True)
                    #     if status == 'update_success':
                    #         coll = self.mongo.create_collection(db, 'applications')
                    #         self.log.info(f"Updating transaction details for application {application_id}")
                    #         status = self.mongo.update_document(coll, {'$set': {'detail.url_store': 'generated'}},
                    #                                             {'application_id': application_id}, upsert=True)
                    #         if status == 'update_success':
                    #             # if user_input['crawl']['url_store'] == 'update':
                    #             #
                    #             #     subject = f"URL Store updated"
                    #             #     message = f"URL Store updated for application {application['detail']['name']} ({application_id})"
                    #             #     util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                    #             #                               message=message, application_id=application_id,
                    #             #                               application_name=application['detail']['name'])
                    #             #     util.Notification().smtp(subject=subject, message=message)
                    #             #     self.log.info(message, notify=True)
                    #             # elif user_input['crawl']['url_store'] == 'replace':
                    #             #
                    #             #     subject = f"URL Store replaced"
                    #             #     message = f"URL Store replaced for application {application['detail']['name']} ({application_id})"
                    #             #     util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                    #             #                               message=message, application_id=application_id,
                    #             #                               application_name=application['detail']['name'])
                    #             #     util.Notification().smtp(subject=subject, message=message)
                    #             #     self.log.info(message, notify=True)
                    #             return 'url_store_update_success'
                    #         else:
                    #             return status
                    #     else:
                    #         return status
                    #
                    from multiprocessing.pool import ThreadPool
                    pool=ThreadPool(processes=3)
                    t1=pool.apply_async(crawl_response)
                    t2=pool.apply_async(crawl_i)
                    return t1.get()

                elif request_state=='pause':
                    crawl_state='paused'
                    end_time=time.time()
                    cops.Crawl(application_id).pause()
                    cache_map['crawl_state']=crawl_state
                    cache_channel.hmset('crawl',{application_id:str(cache_map)})
                    # cops.Crawl.pause()
                    status=self.mongo.update_document(coll,{
                        '$set':{'crawl.crawl_state':crawl_state,'crawl.crawl_paused':end_time}},
                        {'application_id':application_id},upsert=True)
                    if status=='update_success':
                        # TODO: SMTP changes
                        ###########################################
                        subject=f"Crawl operation paused"
                        message=f"Crawl operation paused for application {application['detail']['name']} ({application_id})"
                        # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                        #                           message=message, application_id=application_id,
                        #                           application_name=application['detail']['name'])
                        # util.Notification().smtp(subject=subject, message=message)
                        # self.log.info(message, notify=True)
                        ###########################################

                        return crawl_state

                elif request_state=='resume':
                    crawl_state='resume'
                    end_time=time.time()

                    cops.Crawl(application_id).resume()

                    cache_map['crawl_state']=crawl_state
                    cache_channel.hmset('crawl',{application_id:str(cache_map)})

                    status=self.mongo.update_document(coll,{
                        '$set':{'crawl.crawl_state':crawl_state,'crawl.crawl_resumed':end_time}},
                        {'application_id':application_id},upsert=True)
                    if status=='update_success':
                        return crawl_state

                elif request_state=='terminate':
                    self.log.info(f"Crawl for application {application_id} successfully terminated")
                    start_time=time.time()
                    crawl_state='terminated'
                    end_time=time.time()

                    cops.Crawl(application_id).terminate()

                    cache_map['crawl_state']=crawl_state
                    cache_channel.hmset('crawl',{application_id:str(cache_map)})

                    status=self.mongo.update_document(coll,{
                        '$set':{'crawl.crawl_state':crawl_state,'crawl.crawl_terminated':end_time}},
                        {'application_id':application_id},upsert=True)
                    if status=='update_success':
                        # TODO: SMTP changes
                        ###########################################
                        subject=f"Crawl operation terminated"
                        message=f"Crawl operation terminated for application {application['detail']['name']} ({application_id})"
                        # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Crawl',
                        #                           message=message, application_id=application_id,
                        #                           application_name=application['detail']['name'])

                        # util.Notification().smtp(subject=subject, message=message)
                        # self.log.info(message, notify=True)
                        ###########################################
                        return crawl_state
        finally:
            if db_channel:
                db_channel.close()

    def crawl_verify_authentication(self,application_id,**kwargs):
        try:
            user_input=kwargs.get('crawl')

            self.log.info(f"Revalidating application authentication for {application_id}")
            return 'application_authentication_revalidated'
        finally:
            pass

    def crawl_url_store(self,application_id='',method='',request_state=None,**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'url_store')
                doc=self.mongo.find_document(coll,{'application_id':application_id})
                return doc
            elif method.upper()=='PUT':
                pass
        finally:
            if db_channel:
                db_channel.close()

    def attack(self,application_id='',method='',request_state=None,**kwargs):
        try:
            users_list=[]
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'applications')
            if application_id !='':
                application=self.mongo.find_document(coll,{'application_id':application_id})
                if application == 'document_not_found':
                    return 'document_not_found'
            if method.upper()=='GET':
                coll=self.mongo.create_collection(db,'applications')
                if request_state is None:
                    self.update_CMS_status()
                    applications=self.mongo.find_all_documents(coll)
                    if isinstance(applications,list):
                        attack_eligible=list()
                                 
                        for app in applications:
                            app_detail=dict()
                            if app['app_present'] == True:
                                if 'url_store' in app['detail']: #and app['detail']['instrumentation'] is True:
                                    coll=self.mongo.create_collection(db,'url_store')
                                    url=self.mongo.find_document(coll,{'application_id':app['detail']['id']})
                                    if url!='document_not_found':
                                        if url['authentication']['application_authentication']['login'] == False:
                                            
                                            users_list = copy.copy(app['crawl']['users'])
                                            for i in app['crawl']['users']:
                                                if i['user_id'] != 'user_0':
                                                    users_list.remove(i)
                                                    
                                                
                                            app['crawl']['users']=copy.copy(users_list)
                                            app_detail['crawl']=dict()
                                            app_detail['crawl']['crawl_state']=app['crawl']
                                            app.pop('_id')
                                            app_detail.update(app['detail'])
                                        else:
                                            app_detail['crawl']=dict()
                                            app_detail['crawl']['crawl_state']=app['crawl']
                                            app.pop('_id')
                                            app_detail.update(app['detail'])
                                            
                                        if 'attack' not in app:
                                            app_detail['attack']=dict()
                                            app_detail['attack']['attack_state']='not_instantiated'
                                            app_detail['attack']['attack_completed']=0
                                        elif 'attack' in app:
                                            if 'attack_completed' in app['attack']:
                                                app_detail['attack']=app['attack']
                                            else:
                                                app_detail['attack']=app['attack']
                                                if 'attack_state' not in app['attack']:
                                                    app_detail['attack']['attack_state']='not_instantiated'
                                                app_detail['attack']['attack_completed']=0
                                        if 'payload_policy' in app:
                                            app_detail['payload_policy']=app['payload_policy']
                                        if 'url_store' in app['detail']:
                                            app_detail['url_store']=app['detail']['url_store']
                                        if 'transaction_store' in app['detail']:
                                            app_detail['transaction_store']=app['detail']['transaction_store']
                                        url=self.mongo.find_document(coll,{'application_id':app['detail']['id']})
                                        if url!='document_not_found':
                                            if 'users' in url['authentication']['application_authentication']:
                                                app_detail['users']=dict()
                                                app_detail['users'].update(
                                                    url['authentication']['application_authentication']['users'])
                                        if app_detail:
                                            if len(app['crawl']['users']) != 0:
                                                attack_eligible.append(app_detail)
                                elif 'transaction_store' in app['detail'] : # and app['detail']['instrumentation'] is True:
                                    app_detail.update(app['detail'])

                                    if 'attack' not in app:
                                        app_detail['attack']=dict()
                                        app_detail['attack']['attack_state']='not_instantiated'
                                        app_detail['attack']['attack_completed']=0
                                    elif 'attack' in app:
                                        if 'attack_completed' in app['attack']:
                                            app_detail['attack']=app['attack']
                                        else:
                                            app_detail['attack']=app['attack']
                                            if 'attack_state' not in app['attack']:
                                                app_detail['attack']['attack_state']='not_instantiated'
                                            app_detail['attack']['attack_completed']=0
                                    if 'payload_policy' in app:
                                        app_detail['payload_policy']=app['payload_policy']
                                    if 'url_store' in app['detail']:
                                        app_detail['url_store']=app['detail']['url_store']
                                    if 'transaction_store' in app['detail']:
                                        app_detail['transaction_store']=app['detail']['transaction_store']
                                    url=self.mongo.find_document(coll,{'application_id':app['detail']['id']})
                                    if url!='document_not_found':
                                        if 'users' in url['authentication']['application_authentication']:
                                            app_detail['users']=dict()
                                            app_detail['users'].update(
                                                url['authentication']['application_authentication']['users'])
                                    if app_detail:
                                        attack_eligible.append(app_detail)
                        return attack_eligible
                    elif applications=='documents_not_found':
                        return 'applications_not_found'
                    else:
                        return applications
                elif request_state=='status':
                    self.log.info(f"Checking attack state for application {application_id}")
                    doc=self.mongo.find_document(coll,{'application_id':application_id},{'attack':True})

                    if 'attack' in doc:
                        attack=dict()
                        attack['attack_state']=doc['attack']['attack_state']
                        if 'attack_completed' in doc['attack']:
                            attack['attack_completed']=doc['attack']['attack_completed']
                        return attack
                    else:
                        return 'application_not_attacked'
                elif request_state=='progress':
                    import random
                    return random.randint(1,100)
                elif request_state=='status_progress':
                    if cache_channel.exists('attack'):
                        attacking_apps=cache_channel.hgetall('attack')
                        status_progress=list()
                        for k,v in attacking_apps.items():
                            status_progress.append(util.ConvertData(v.decode('utf-8')).framework_compatible())
                        return status_progress
                    else:
                        self.log.critical(f"Attack not in progress for any applications")
                        return 'applications_not_available'
                elif request_state=='logs':
                    user_input=kwargs.get('attack')

                    if user_input['download'] is None:
                        # file = f"{env.workspace}\\artefacts\\traces\\execution.log"
                        file=f"{env.workspace}/artefacts/traces/execution.log"
                        with open(file,'r') as fo:
                            if user_input['lines']!='all':
                                content_filter=list()
                                for line in fo.readlines():
                                    if user_input['level']:
                                        if user_input['level'].upper() in line:
                                            content_filter.append(line.strip())
                                    else:
                                        content_filter.append(line.strip())
                                return content_filter[-int(user_input['lines']):]
                            else:
                                content_filter=list()
                                for line in fo.readlines():
                                    content_filter.append(line.strip())
                                return content_filter
                    elif user_input['download'].lower()=='true':
                        # log_file_path = f"{env.workspace}\\artefacts\\traces\\execution.log"
                        log_file_path=f"{env.workspace}/artefacts/traces/execution.log"
                        return log_file_path

            elif method.upper()=='POST':
                user_input=kwargs.get('attack')
                pool=ThreadPool(processes=3)

                cache_map=dict()
                cache_map['application_id']=application_id
                  
                if request_state=='instantiate' or request_state=='resume':
                    if str(application['detail']['state']) not in ['crawling']:
                        self.log.info(f"Instantiating attack for application {application_id}")

                        def api_response():
                            start_time=time.time()
                            cache_map={'application_id':application_id,'attack_state':'instantiated'}
                            cache_channel.hmset('attack',{application_id:str(cache_map)})
                            cache_channel.hset(application_id,'attack_state','instantiated')
                            # attack_state = 'instantiated'
                            # cache_map['attack_state'] = attack_state
                            # cache_channel.hmset('attack', {application_id: str(cache_map)})

                            coll=self.mongo.create_collection(db,'applications')
                            self.mongo.update_document(coll,{'$set':{'detail.state':'attacking'}},
                                {'application_id':application_id},upsert=True)
                            self.mongo.update_document(coll,{'$set':{'attack.attack_state':'instantiated',
                                'attack.attack_instantiated':start_time}},
                                {'application_id':application_id},upsert=True)

                            application=self.mongo.find_document(coll,{'application_id':application_id})
                            message=f"Attack operation instantiated for application {application['detail']['name']} ({application_id})"
                            util.Notification().send_notification(message=message,
                                application_id=application_id,
                                operation='Attack',
                                application_name=application['detail']['name'])
                            return 'instantiated'

                        def instantiate():
                            # cache_map = {'application_id': application_id,  'attack_state':  'in_progress'}
                            # cache_channel.hmset('attack', {application_id: str(cache_map)})
                            # cache_channel.hset(application_id, 'attack_state', 'in_progress')

                            coll=self.mongo.create_collection(db,'applications')
                            self.mongo.update_document(coll,{'$set':{'detail.state':'attacking'}},
                                {'application_id':application_id},upsert=True)
                            self.mongo.update_document(coll,{'$set':{'attack.attack_state':'in_progress'}},
                                {'application_id':application_id},upsert=True)

                            # changedbypt
                            cache_map={'application_id':application_id,'attack_state':'in_progress'}
                            cache_channel.hmset('attack',{application_id:str(cache_map)})
                            cache_channel.hset(application_id,'attack_state','in_progress')

                            self.log.info(f"Revalidating application existence on CMS")

                            self.log.info(f"Checking token expiry status")
                            if cache_channel.exists('cms'):
                                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                            else:
                                self.log.critical(f"CMS is not configured to fetch applications")
                                return 'cms_not_configured'
                            access_token=CMS(cms['ipv4_address']).token_status()

                            self.log.info(f"Querying CMS for application {application_id}")
                            cms_services_header=util.Authentication().create_http_header('services',access_token,
                                cms['ipv4_address'])
                            application_status=CMS(cms['ipv4_address']).application_status(application_id,
                                cms_services_header)
                            print('appliation_status',application_status)
                            # if application_status is None:
                            #     end_time=time.time()
                            #     self.log.critical(f"Application {application_id} does not exist in CMS")

                            #     cache_map={'application_id':application_id,'attack_state':'aborted'}
                            #     cache_channel.hmset('attack',{application_id:str(cache_map)})

                            #     cache_channel.hset(application_id,'attack_state','aborted')
                            #     coll=self.mongo.create_collection(db,'applications')
                            #     self.mongo.update_document(coll,{
                            #         '$set':{'attack.attack_state':'aborted',
                            #             'attack.attack_aborted':end_time}},
                            #         {'application_id':application_id},upsert=True)
                            #     self.mongo.update_document(coll,{'$set':{'detail.state':'aborted'}},
                            #         {'application_id':application_id},upsert=True)
                            #     return 'application_not_available'
                            # #elif application_status in ['NORMAL','THREAT','ATTACK']:  # PROVISIONED
                            # else:
                            self.log.info(f"Application Status got pickedd {application_status}")
                            # cms_pool_status[application_id]=True
                            cache_channel.hset(application_id,"cms_pool_status",str({"pool_status":"CMS_OK"}))
                            cache_channel.hset(application_id,"attack_status",str({"attack_status":"ATTACK_OK"}))
                            #self.start_attack(cache_channel,db,application_id)
                            s1=threading.Thread(target=CMS(cms['ipv4_address']).pool_CMS_status,args=[application_id])
                            s2=threading.Thread(target=self.start_attack,args=[cache_channel,db,application_id])
                            s1.name=f"pool_cms_{application_id}"
                            s2.name=f"start_attack_{application_id}"
                            s1.start()
                            s2.start()
                            # else:
                            #     end_time=time.time()
                            #     cache_map={'application_id':application_id,'attack_state':'aborted'}
                            #     cache_channel.hmset('attack',{application_id:str(cache_map)})

                            #     cache_channel.hset(application_id,'attack_state','aborted')
                            #     coll=self.mongo.create_collection(db,'applications')
                            #     self.mongo.update_document(coll,{
                            #         '$set':{'attack.attack_state':'aborted',
                            #             'attack.attack_aborted':end_time}},
                            #         {'application_id':application_id},upsert=True)
                            #     self.mongo.update_document(coll,{'$set':{'detail.state':'aborted'}},
                            #         {'application_id':application_id},upsert=True)
                            #     self.log.critical(
                            #         f"Attack Aborted! App ID: {application_id} Application status in CMS found :'{application_status}'")
                            #     util.Notification().send_notification(
                            #         message="Attack aborting as App status in CMS was not in 'NORMAL'/'THREAT'/'ATTACK'",
                            #         application_id=application_id,
                            #         operation="Attack",
                            #         application_name=application['detail']['name'],
                            #         subject=f"Attack aborted for App: {application['detail']['name']}"
                            #     )
                            #     return 'application_not_available'

                        t1=pool.apply_async(api_response)
                        t2=pool.apply_async(instantiate)

                        return t1.get()
                        # from threading import Thread, Lock
                        # from queue import Queue
                        # q = Queue()
                        # t1 = Thread(target=attack_response, args=(q,), daemon=True)
                        # t2 = Thread(target=attack_i, args=())
                        # t1.start()
                        # t2.start()
                        # return q.get()
                    return 'crawl_not_instantiated'
                elif request_state=='pause':
                    self.log.info(f"Attack for application {application_id} successfully paused")
                    start_time=time.time()
                    attack_state='paused'
                    end_time=time.time()
                    # TODO: SMTP changes
                    ###########################################
                    subject=f"Attack operation paused"
                    message=f"Attack operation paused for application {application['detail']['name']} ({application_id})"
                    # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Attack',
                    #                           message=message, application_id=application_id,
                    #                           application_name=application['detail']['name'])
                    util.Notification().smtp(subject=subject,message=message)
                    self.log.info(message,notify=True)
                    ########################################

                    cache_map['attack_state']=attack_state
                    cache_channel.hmset('attack',{application_id:str(cache_map)})
                    cache_channel.hset(application_id,'attack_state',attack_state)
                    coll=self.mongo.create_collection(db,'applications')
                    # status = self.mongo.update_document(coll, {
                    #     '$set': {'attack.attack_state': attack_state, 'attack.attack_paused': end_time,
                    #              'attack.attack_pause_request_count': 0 }}, #chg
                    #                                     {'application_id': application_id}, upsert=True)
                    time.sleep(5)
                    doc=self.mongo.find_document(coll,{'application_id':application_id},{'attack':True})
                    if doc['attack']['attack_state']=="paused":
                        return doc['attack']['attack_state']
                    else:
                        time.sleep(10)
                        doc=self.mongo.find_document(coll,{'application_id':application_id},{'attack':True})
                        return doc['attack']['attack_state']

                    # if status == 'update_success':
                    #     return attack_state
                elif request_state=='terminate':
                    self.log.info(f"Attack for application {application_id} successfully terminated")
                    attack_state='terminated'
                    end_time=time.time()
                    import psutil

                    # appstore_coll = self.mongo.create_collection(db, 'applications')
                    # doc = self.mongo.find_document(appstore_coll, {"username": user_input['username']})

                    print(f"Added Signal.Stop Code too. ppid value is  {os.getppid()}")
                    os.kill(os.getppid(),signal.SIGSTOP)  # signal.SIGSTOP
                    # TODO: SMTP changes
                    ###########################################
                    # print('i' * 1000)
                    # return 1
                    subject=f"Attack operation terminated"
                    message=f"Attack operation terminated for application {application['detail']['name']} ({application_id})"
                    # util.Notification().flash(timestamp=time.time(), level='INFO', operation='Attack',
                    #                           message=message, application_id=application_id,
                    #                           application_name=application['detail']['name'])
                    util.Notification().smtp(subject=subject,message=message)
                    self.log.info(message,notify=True)
                    ########################################
                    cache_map['attack_state']=attack_state
                    cache_channel.hmset('attack',{application_id:str(cache_map)})
                    cache_channel.hset(application_id,'attack_state',attack_state)
                    coll=self.mongo.create_collection(db,'applications')
                    status=self.mongo.update_document(coll,{
                        '$set':{'attack.attack_state':attack_state,'attack.attack_terminated':end_time}},
                        {'application_id':application_id},upsert=True)

                    self.log.info(f"Checking attack state for application {application_id}")
                    doc=self.mongo.find_document(coll,{'application_id':application_id},{'attack':True})

                    if 'attack' in doc:
                        state=dict()
                        state['attack_state']=doc['attack']['attack_state']
                        if 'attack_completed' in doc['attack']:
                            state['attack_terminated']=doc['attack']['attack_terminated']

                    if status=='update_success':
                        return attack_state,state
        finally:
            if db_channel:
                db_channel.close()

    def attack_application(self,application_id,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            user_input=kwargs.get('attack')
            self.log.info(f"Updating application {application_id} with attack configurations")
            coll=self.mongo.create_collection(db,'applications')

            db_map=dict()
            for k,v in user_input['attack'].items():
                db_map[f"attack.{k}"]=v

            self.log.info(f"Updating database for application {application_id}")
            status=self.mongo.update_document(coll,{'$set':db_map},{'application_id':application_id},
                upsert=True)

            if 'users' in user_input['attack']:
                for k,v in user_input['attack']['users'].items():
                    # cache_channel.hset(application_id, 'attack_user', v['username'])
                    cache_channel.hset(application_id,'attack_user',str(v))
            if status=='update_success':
                self.log.info(f"Application updated successfully with attack configuration")
                return 'application_updated'
            return 'success'
        finally:
            if db_channel:
                db_channel.close()

    def attack_verify_authentication(self,application_id,**kwargs):
        try:
            user_input=kwargs.get('attack')

            self.log.info(f"Revalidating application authentication for {application_id}")
            return 'application_authentication_revalidated'
        finally:
            pass

    def attack_store(self,application_id='',method='',request_state=None,**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                if request_state=='url_store':
                    coll=self.mongo.create_collection(db,'url_store')
                    doc=self.mongo.find_document(coll,{'application_id':application_id})
                    return doc
                elif request_state=='transaction_store':
                    coll=self.mongo.create_collection(db,'transaction_store')
                    doc=self.mongo.find_document(coll,{'application_id':application_id})
                    return doc
            elif method.upper()=='PUT':
                pass
        finally:
            if db_channel:
                db_channel.close()

    def attack_policy(self,method='',policy_name='',**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            if method.upper()=='GET':
                if not policy_name:
                    self.log.info(f"Fetching configured attack policies")
                    coll=self.mongo.create_collection(db,'configuration')
                    doc=self.mongo.find_document(coll,{'api_version':'1.0'})
                    if isinstance(doc,dict):
                        if 'attack_policy' in doc:
                            return doc['attack_policy']
                        else:
                            return 'attack_policy_not_found'
                    else:
                        return doc
                if policy_name:
                    self.log.info(f"Fetching attack policy: {policy_name}")
                    coll=self.mongo.create_collection(db,'configuration')
                    policy=self.mongo.find_document(coll,{'api_version':'1.0'},{'attack_policy':1})
                    return policy['attack_policy'][f'{policy_name}']
            if method.upper()=='POST':
                user_input=kwargs.get('attack_policy')
                self.log.info(f"Creating new attack policy")
                coll=self.mongo.create_collection(db,'configuration')
                for k,v in user_input['attack_policy'].items():
                    status=self.mongo.update_document(coll,{'$set':{f'attack_policy.{k}':v}},
                        {'api_version':'1.0'})
                if status=='update_success':
                    self.log.info(f"Attack policy updated successfully")
                    return 'attack_policy_updated'
                else:
                    self.log.critical(f"Attack policy could not update successfully")
                    return status
        finally:
            if db_channel:
                db_channel.close()

    def reports(self):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Fetching reports from database")
            coll=self.mongo.create_collection(db,'reports')
            app_coll=self.mongo.create_collection(db,'applications')
            current_application= self.mongo.find_documents(app_coll, {'app_present': True})
            current_app_ids = []
           
            for app_id in current_application:
                current_app_ids.append(app_id['application_id'])

            docs=self.mongo.find_all_documents(coll)

            if docs!='documents_not_found':
                self.log.info(f"{len(docs)} available in database")
                return_map=list()
                for doc in docs:
                    if doc['application_details']['application_id'] in current_app_ids:
                        report=dict()
                        report['report_id']=doc['report_id']
                        report['report_name']=doc['report_name']
                        report['report_version']=doc['report_version']
                        report['application_id']=doc['application_details']['application_id']
                        report['application_name']=doc['application_details']['application_name']
                        report['application_url']=doc['application_details']['application_url']
                        report['scan_datetime']=doc['application_details']['scan_end_time']  # ajchg
                        return_map.append(report)
                return return_map
            else:
                return docs
        finally:
            if db_channel:
                db_channel.close()

    def report_download(self,report_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Fetching report {report_id}")
            coll=self.mongo.create_collection(db,'reports')
            doc=self.mongo.find_document(coll,{'report_id':report_id})
            if doc=='document_not_found':
                self.log.info(f"Report is not available to be downloaded")
                return 'report_not_found'
            if doc!='document_not_found' or doc!='connection_error':
                self.log.info(f"Report is ready to be downloaded")
                doc.pop('_id')
                return_map=dict()
                return_map['report']=doc
                return return_map
            else:
                self.log.info(f"Report is not ready to be downloaded")
                return doc
        finally:
            if db_channel:
                db_channel.close()

    def report_compensating_control(self,report_id,method,**kwargs):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                self.log.info(f"Fetching compensating control for {report_id}")
                vulnarability=dict()
                vulnarabilities=[]
                cc=[]
                cc_copy=dict()
                coll=self.mongo.create_collection(db,'reports')
                doc=self.mongo.find_document(coll,{'report_id':report_id})
                if doc=='document_not_found':
                    return 'report_not_found'
                if doc!='document_not_found' or doc!='connection_error':
                    self.log.info(f"Processing report to generate compensating control")

                    # cc = dummy.cc
                    for k,v in doc['services'].items():
                        vulnarabilities=v['vulnerabilities']

                    for k,v in vulnarabilities.items():
                        cc_copy=v
                        cc.append(cc_copy)

                    return_map=dict()
                    return_map['compensating_control']=dict()
                    return_map['compensating_control']['report_id']=report_id
                    return_map['compensating_control']['vulnerabilities']=cc
                    return return_map
                else:
                    self.log.info(f"Report is not ready to be downloaded")
                    return doc
            elif method.upper()=='POST':
                user_input=kwargs.get('compensating_control')

                # vulnerable_dict = {'CAPEC-A1-SQLi': 'SQLi_Rule_template_v1.0.txt',
                #                'CAPEC-A1-CMDi': 'CMDi_Rule_template_v1.0.txt',
                #                'CAPEC-A5-PathTraversal': 'LFI_Rule_template_v1.0.txt',
                #                'CAPEC-A7-ReflectiveXSS': 'XSS_Rule_template_v1.0.txt',
                #                'CAPEC-A5-RFI': 'RFI_Rule_template_v1.0.txt'}
                id=random.randint(0000,9999)

                self.log.info(f"Generating compensating control for report: {report_id}")
                self.log.info(f"Parsing {user_input}")
                output=[]
                for key,value in user_input.items():
                    for k,v in value.items():
                        for k1,v1 in v.items():
                            print(v1['vulnerability_name'])
                            if type(v1)==type(dict()):
                                contents=was.was[f"{v1['vulnerability_name']}"]
                                for key,value in v1['urls'].items():
                                    for k,v in value.items():
                                        uri=contents.replace("VULN-URL",v['uri'])
                                        for k,v in value.items():
                                            if 'parameters' in v:
                                                if 'parameter_name' in v['parameters']:
                                                    parameter=uri.replace('ARGUMENT-NAME',
                                                        v['parameters']['parameter_name'])

                                                    ruleId=parameter.replace("RULE_ID",str(id))
                                                    id+=1
                                                    output.append(ruleId)
                                            else:
                                                parameter=uri.replace('ARGUMENT-NAME'," ")
                                                ruleId=parameter.replace('RULE_ID',str(id))
                                                id+=1
                                                output.append(ruleId)

                return output


        finally:
            if db_channel:
                db_channel.close()

    def configuration(self,method='',request_type=None,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            if method.upper()=='GET':
                return_map=dict()

                coll=self.mongo.create_collection(db,'configuration')
                if request_type is None:
                    config_doc=self.mongo.find_document(coll,{'api_version':'1.0'})
                elif request_type is not None:
                    config_doc=self.mongo.find_document(coll,{'api_version':'1.0'},{request_type:1})
                    if request_type=='integration':
                        return_map['integration']=dict()
                        return_map['integration']['keys']=list()
                        coll=self.mongo.create_collection(db,'vault')
                        vault_doc=self.mongo.find_all_documents(coll)
                        if isinstance(vault_doc,list):
                            for doc in vault_doc:
                                integration=dict()
                                if 'integration' in doc:
                                    if cache_channel.exists(doc['integration']['ipv4_address']):
                                        token=cache_channel.get(doc['integration']['ipv4_address'])
                                        integration['token']=token.decode('utf-8')[-5:]

                                        validity=cache_channel.ttl(doc['integration']['ipv4_address'])
                                        integration['validity']=math.ceil(validity/(3600*24))
                                        # if integration['validity'] <= math.ceil(integration['validity']/10):
                                        if integration['validity']<=math.ceil(
                                                integration['validity']-(0.1*integration['validity'])):
                                            integration['renew']=True
                                            self.log.warning(
                                                f"Integration key for {doc['integration']['ipv4_address']} is going to get expired in {integration['validity']} days",
                                                notify=True)
                                            subject='Integration Key Expiry'
                                            message=f"Integration key for {doc['integration']['ipv4_address']} is going to get expired in {integration['validity']} days"
                                            util.Notification().send_notification(message=message,
                                                operation='Configuration',
                                                subject=subject)
                                            util.Notification().smtp(subject=subject,message=message)

                                        else:
                                            integration['renew']=False
                                    else:
                                        self.log.warning(
                                            f"Integration key for {doc['integration']['ipv4_address']} expired",
                                            notify=True)
                                        subject='Integration Key Expired!'
                                        message=f"Integration key for {doc['integration']['ipv4_address']} is expired"
                                        util.Notification().flash(timestamp=time.time(),level='WARNING',
                                            operation='Integration',
                                            message=message)
                                        util.Notification().smtp(subject=subject,message=message)

                                    integration['ipv4_address']=doc['integration']['ipv4_address']
                                    integration['note']=doc['integration']['note']
                                    integration['issued']=doc['integration']['issued']
                                    return_map['integration']['keys'].append(integration)
                                    print(integration)

                if config_doc!='document_not_found':
                    if 'file_upload_policy' in config_doc:
                        return_map['file_upload_policy']=config_doc['file_upload_policy']
                    if 'database_policy' in config_doc:
                        return_map['database_policy']=config_doc['database_policy']
                    if 'logging_policy' in config_doc:
                        return_map['logging_policy']=config_doc['logging_policy']
                    if 'attack_policy' in config_doc:
                        return_map['attack_policy']=config_doc['attack_policy']
                    if 'syslog' in config_doc:
                        return_map['syslog']=config_doc['syslog']
                    if 'cms' in config_doc:
                        try:
                            if cache_channel.exists('cms'):
                                cms_details=util.ConvertData(
                                (cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                                check_key=cms_details['ipv4_address']
                                current_IP=check_key.replace('.','_')
                                if 'authorization_token' in config_doc['cms'][current_IP]:
                                    config_doc['cms'][current_IP].pop('authorization_token')
                                return_map['cms']=config_doc['cms'][current_IP]
                        except Exception:
                            pass
                            
                    if 'email' in config_doc:
                        return_map['email']=config_doc['email']
                    if 'integration' in config_doc:
                        if request_type is None:
                            return_map['integration']=dict()
                        return_map['integration']['configuration']=config_doc['integration']
                    if 'api_version' in config_doc:
                        return_map['api_version']=config_doc['api_version']
                # coll = self.mongo.create_collection(db, 'configuration')
                # config_doc = self.mongo.find_document(coll, {'api_version': '1.0'})
                # if isinstance(config_doc, dict):
                #     return_map['integration']['minimum'] = config_doc['integration']['minimum']
                #     return_map['integration']['maximum'] = config_doc['integration']['maximum']
                #     return_map['integration']['default'] = config_doc['integration']['default']
                return return_map

            elif method.upper()=='PUT':
                user_input=kwargs.get('configuration')
                self.log.info(f"Updating WAS configuration")

                if 'cms' in user_input:
                    self.log.info(f"Validating CMS credentials")

                    self.log.debug(f"Generating CMS authentication header")
                    authentication_header=util.Authentication().create_http_header('authentication',
                        cms.cms['authorization_token'],
                        user_input['cms']['ipv4_address'])
                    self.log.debug(f"Attempting to login to CMS {user_input['cms']['ipv4_address']}")
                    login_detail=CMS(user_input['cms']['ipv4_address']).login(username=user_input['cms']['username'],
                        password=user_input['cms']['password'],
                        header=authentication_header)

                    cms_services_header=util.Authentication().create_http_header('services',
                        login_detail['access_token'],
                        user_input['cms']['ipv4_address'])

                    cms_version_details=CMS(user_input['cms']['ipv4_address']).cms_version_check(
                        header=cms_services_header)

                    if 'error' not in login_detail:
                        if cms_version_details['major']=='1.4':
                            vault_map=dict()
                            if 'username' in user_input['cms']:
                                vault_map['username']=user_input['cms']['username']
                                vault_map['type']='cms'
                                vault_map['ipv4_address']=user_input['cms']['ipv4_address']
                                if 'password' in user_input['cms']:
                                    self.log.debug(f"Encrypting password with SHA256")
                                    encrypted_password,key=util.Authentication().encrypt_password(
                                        user_input['cms']['password'])
                                    vault_map['password']=encrypted_password
                                    vault_map['key']=key
                                    coll=self.mongo.create_collection(db,'vault')
                                    status=self.mongo.update_document(coll,{'$set':vault_map},
                                        {'username':vault_map['username']},
                                        upsert=True)
                                    if status=='update_success':
                                        self.log.debug(f"Credentials encrypted and saved successfully")
                                        user_input['cms'].pop('password')

                                        self.log.info(f"Updating cache with CMS details")
                                        cache_map=user_input
                                        cache_map['cms']['authorization_token']=cms.cms['authorization_token']
                                        status=cache_channel.set('cms',str(cache_map['cms']))
                                        if status is True:
                                            self.log.info(f"Updating cache with CMS user details")
                                            cache_map=dict()
                                            cache_map['username']=user_input['cms']['username']
                                            cache_map['user_id']=login_detail['additionalDetails']['userId']
                                            cache_map['type']='cms'
                                            cache_map['access_token']=login_detail['access_token']
                                            cache_map['refresh_token']=login_detail['refresh_token']
                                            cache_map['ipv4_address']=user_input['cms']['ipv4_address']
                                            cache_channel.setex(user_input['cms']['username'],
                                                login_detail['expires_in'],
                                                str(cache_map))

                                            coll=self.mongo.create_collection(db,'configuration')
                                            config=self.mongo.find_document(coll,{'api_version':'1.0'})

                                            if 'cms' in config:
                                                cms_details=config
                                                replace_key=user_input['cms']['ipv4_address'].replace('.','_')
                                                if "ae" in config["cms"].get(replace_key,{}).keys():
                                                    user_input['cms']["ae"]=config["cms"][replace_key]["ae"]
                                                
                                                vm_user_name = ''
                                                if replace_key in cms_details['cms'] and 'vm_username' in cms_details['cms'][replace_key]:
                                                    vm_user_name = cms_details['cms'][replace_key]['vm_username']
                                                    
                                                user_input['cms'].update({"vm_username":vm_user_name})
                                                cms_details['cms'][replace_key]=user_input['cms']
                                            else:
                                                cms_details={}
                                                cms_details['cms']={}
                                                replace_key=user_input['cms']['ipv4_address'].replace('.','_')
                                                cms_details['cms'][replace_key]=user_input['cms']

                                            status=self.mongo.update_document(coll,{'$set':cms_details},
                                                {'api_version':'1.0'},
                                                upsert=True)
                                            if status=='update_success':
                                                self.log.info(f"CMS configuration updated successfully")
                                                self.applications()
                                                return 'cms_update_success',None
                                            else:
                                                return status,None
                                        else:
                                            self.log.critical(f"Cache update status: {status}")
                                            return status,None
                                    else:
                                        return status,None
                        else:
                            self.log.critical(f"CMS version is not compatible with was{cms_version_details['major']}")
                            return 'cms_version_error',None

                    elif login_detail=='connection_error':
                        return 'cms_connection_error',None
                    elif login_detail['error']=='unauthorized' or login_detail['error']=='unauthorized_user':
                        self.log.critical(f"CMS authentication status: {login_detail['error_description']}")
                        return 'cms_authentication_error',login_detail['error_description']

                if 'syslog' in user_input:
                    vault_map=dict()
                    if 'username' in user_input['syslog']:
                        vault_map['username']=user_input['syslog']['username']
                        vault_map['type']='syslog'
                        if 'password' in user_input['syslog']:
                            encrypted_password,key=util.Authentication().encrypt_password(
                                user_input['syslog']['password'])
                            vault_map['password']=encrypted_password
                            vault_map['key']=key
                            self.log.debug(f"Updating syslog credentials to vault")
                            coll=self.mongo.create_collection(db,'vault')
                            status=self.mongo.update_document(coll,{
                                '$set':{'password':vault_map['password'],'key':vault_map['key']}},
                                {'username':vault_map['username']},
                                upsert=True)
                            if status=='update_success':
                                self.log.info(f"Credentials encrypted and saved successfully")
                                user_input['syslog'].pop('password')
                            else:
                                return status,None
                    self.log.info(f"Updating syslog configuration to cache")
                    cache_channel.hset('configuration','syslog',str(user_input['syslog']))

                    self.log.info(f"Updating syslog configuration to database")
                    coll=self.mongo.create_collection(db,'configuration')
                    status=self.mongo.update_document(coll,{'$set':user_input},{'api_version':'1.0'},upsert=True)
                    if status=='update_success':
                        self.log.info(f"Syslog configuration updated successfully")
                        return 'syslog_update_success',None
                    else:
                        return status,None

                if 'email' in user_input:
                    vault_map=dict()
                    if 'sender' in user_input['email']:
                        vault_map['sender']=user_input['email']['sender']
                        vault_map['type']='email'
                        if 'password' in user_input['email']:
                            # TODO SMTP: Murali changes
                            ########################################
                            status=util.Email().validate(smtp_host=user_input['email']['smtp_host'],
                                smtp_port=user_input['email']['smtp_port'],
                                protocol=user_input['email']['protocol'],
                                sender=user_input['email']['sender'],
                                password=user_input['email']['password'],
                                receiver=user_input['email']['recipients'])
                            ########################################
                            if status==235:
                                self.log.info(f"SMTP authentication successful")
                            elif isinstance(status,smtplib.SMTPAuthenticationError):
                                self.log.error(f"SMTP credentials are invalid")
                                return 'smtp_authentication_error',None
                            elif isinstance(status,smtplib.SMTPConnectError):
                                self.log.error(f"SMTP server is unreachable")
                                return 'smtp_connection_error',None
                            elif isinstance(status,smtplib.SMTPNotSupportedError):
                                self.log.error(f"SMTP server is unreachable")
                                return 'smtp_not_supported_error',None
                            elif isinstance(status,ConnectionResetError):
                                self.log.error(f"Connection reset by SMTP server")
                                return 'connection_reset_error',None
                            # TODO SMTP: Murali changes
                            #############################################
                            elif isinstance(status,Exception):
                                self.log.error(f"Exception raise when setting up SMTP server")
                                return 'exception',None
                            #############################################
                            encrypted_password,key=util.Authentication().encrypt_password(
                                user_input['email']['password'])
                            vault_map['password']=encrypted_password
                            vault_map['key']=key

                            self.log.debug(f"Updating email credentials to vault")
                            coll=self.mongo.create_collection(db,'vault')
                            status=self.mongo.update_document(coll,{
                                '$set':{'password':vault_map['password'],'key':vault_map['key']}},
                                {'sender':vault_map['sender']},
                                upsert=True)
                            if status=='update_success':
                                self.log.info(f"Credentials encrypted and saved successfully")
                                user_input['email'].pop('password')
                            else:
                                return status,None
                    self.log.info(f"Updating email configuration to cache")
                    cache_channel.hset('configuration','email',str(user_input['email']))

                    self.log.info(f"Updating email configuration to database")
                    coll=self.mongo.create_collection(db,'configuration')
                    status=self.mongo.update_document(coll,{'$set':user_input},{'api_version':'1.0'},upsert=True)
                    if status=='update_success':
                        self.log.info(f"Email configuration updated successfully")
                        return 'email_update_success',None
                    else:
                        return status,None

                if 'database_policy' in user_input:
                    coll=self.mongo.create_collection(db,'configuration')
                    doc=self.mongo.find_document(coll,{'api_version':'1.0'})
                    if doc=='document_not_found' or doc!='document_not_found':
                        status=self.mongo.update_document(coll,{
                            '$set':{'database_policy':user_input['database_policy']}},
                            {'api_version':'1.0'},upsert=True)
                        if status=='update_success':
                            self.log.info(f"Database policy updated successfully")
                            cache_channel.hset('dashboard','threshold',user_input['database_policy']['archive'])
                            return 'database_update_success',None
                        else:
                            self.log.info(f"Database policy could not update successfully")
                            return status,None
                    else:
                        return doc

                vault_map,update_status=dict(),set()
                for k,v in user_input.items():
                    # if cache_channel.ttl(k) > 0 and cache_channel.ttl(user_input[k]['username']) > 0:
                    #     cache_channel.persist(k)
                    #     cache_channel.expire(user_input[k]['username'], 10800)
                    #
                    # if 'username' in user_input[k]:
                    #     vault_map['username'] = user_input[k]['username']
                    #     vault_map['type'] = k
                    #     if isinstance(v, dict):
                    #         if 'password' in user_input[k]:
                    #             encrypted_password, key = util.Authentication().encrypt_password(user_input[k]['password'])
                    #             vault_map['password'] = encrypted_password
                    #             vault_map['key'] = key
                    #             coll = self.mongo.create_collection(db, 'vault')
                    #             doc = self.mongo.find_document(coll, {'username': user_input[k]['username']})
                    #             if doc == 'document_not_found':
                    #                 status = self.mongo.insert_document(coll, vault_map)
                    #             elif doc != 'document_not_found':
                    #                 status = self.mongo.update_document(coll, {'$set': {'password': vault_map['password'], 'key': vault_map['key']}}, {'username': vault_map['username']})
                    #             if status == 'insert_success' or status == 'update_success':
                    #                 self.log.info(f"Credentials encrypted and saved successfully")
                    #             else:
                    #                 return status
                    #
                    #             user_input[k].pop('password')
                    #             if k == 'cms':
                    #                 user_input[k]['authorization_token'] = cms.cms['authorization_token']

                    coll=self.mongo.create_collection(db,'configuration')
                    doc=self.mongo.find_document(coll,{'api_version':'1.0'})
                    if doc=='document_not_found' or doc!='document_not_found':
                        status=self.mongo.update_document(coll,{'$set':user_input},{'api_version':'1.0'},
                            upsert=True)
                        update_status.add(status)
                    else:
                        return doc

                status=[i for i in update_status if len(update_status)==1]
                if status[0]=='update_success':
                    return status[0],None
                else:
                    return status[0],None
        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()

    def configuration_integration(self,method='',**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            user_input=kwargs.get('configuration')

            if user_input['integration']['type']=='generate':
                token=util.Authentication().generate_token2(32)
                hashed_token=util.Authentication().hash_password(token)
                user_input['integration']['password']=hashed_token
                expiry=3600*24*int(user_input['integration']['expiry'])
                self.log.debug(f"Updating integration details in cache for user_input['integration']['ipv4_address']")
                cache_channel.setex(user_input['integration']['ipv4_address'],expiry,
                    token)
                self.log.debug(
                    f"Updating integration details in database for {user_input['integration']['ipv4_address']}")
                vault_map=dict()
                vault_map['integration']=user_input['integration']
                vault_map['integration']['issued']=time.time()
                coll=self.mongo.create_collection(db,'vault')
                status=self.mongo.update_document(coll,{'$set':vault_map},
                    {'ipv4_address':user_input['integration']['ipv4_address']},
                    upsert=True)
                # status = self.mongo.update_document(coll, {'$set': {'integration': user_input['integration']}},
                #                                  {'ipv4_address': user_input['integration']['ipv4_address']},
                #                                  upsert=True)
                if status=='update_success':
                    return_map=dict()
                    return_map['configuration']=dict()
                    return_map['configuration']['integration']=dict()
                    return_map['configuration']['integration']['ipv4_address']=user_input['integration'][
                        'ipv4_address']
                    return_map['configuration']['integration']['token']=token
                    return return_map
                else:
                    return status
            elif user_input['integration']['type']=='renew':
                expiry=3600*24*int(user_input['integration']['expiry'])
                cache_channel.expire(user_input['integration']['ipv4_address'],expiry)
                return 'token_renewed'
            elif user_input['integration']['type']=='revoke':
                self.log.debug(
                    f"Removing integration details from cache for {user_input['integration']['ipv4_address']}")
                cache_channel.delete(user_input['integration']['ipv4_address'])
                self.log.debug(
                    f"Removing integration details from database for {user_input['integration']['ipv4_address']}")
                coll=self.mongo.create_collection(db,'vault')
                status=self.mongo.delete_document(coll,{'ipv4_address':user_input['integration']['ipv4_address']})
                if status=='delete_success':
                    return 'token_revoked'
        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()

    def configuration_check(self,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])

            configuration=kwargs.get('configuration')
            for k,v in configuration.items():
                if k=='cms':
                    self.log.info(f"Validating CMS credentials")

                    self.log.debug(f"Generating CMS authentication header")
                    authentication_header=util.Authentication().create_http_header('authentication',
                        cms.cms['authorization_token'],
                        configuration[k]['ipv4_address'])
                    self.log.debug(f"Attempting to login to CMS {configuration[k]['ipv4_address']}")
                    login_detail=CMS(configuration[k]['ipv4_address']).login(username=configuration[k]['username'],
                        password=configuration[k]['password'],
                        header=authentication_header)
                    if 'error' not in login_detail:
                        self.log.info(f"Updating cache with CMS details")
                        cache_map=configuration
                        cache_map['cms'].pop('password')
                        cache_map['cms']['authorization_token']=cms.cms['authorization_token']
                        status=cache_channel.setex(k,login_detail['refresh_token'],str(cache_map['cms']))
                        if status is True:
                            self.log.info(f"Updating cache with CMS user details")
                            cache_map=dict()
                            cache_map['username']=configuration[k]['username']
                            cache_map['user_id']=login_detail['additionalDetails']['userId']
                            cache_map['type']=k
                            cache_map['access_token']=login_detail['access_token']
                            cache_map['refresh_token']=login_detail['refresh_token']
                            status=cache_channel.setex(configuration[k]['username'],login_detail['refresh_token'],
                                str(cache_map))
                            if status is True:
                                return 'success',None
                            else:
                                self.log.critical(f"Cache update status: {status}")
                                return status,None
                        else:
                            self.log.critical(f"Cache update status: {status}")
                            return status,None
                    elif login_detail=='connection_error':
                        return login_detail,None
                    else:
                        self.log.critical(f"CMS authentication status: {login_detail['error_description']}")
                        return login_detail['error'],login_detail['error_description']

                elif k=='vsp':
                    return 'success'
                elif k=='integration':
                    return 'success'
                elif k=='proxy':
                    return 'success'
                elif k=='syslog':
                    return 'success'
        finally:
            if cache_channel:
                del cache_channel

    def notification(self,method,**kwargs):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])

            if method=='GET':
                user_input=kwargs.get('notifications')
                self.log.info(f"Checking notifications in buffer")
                if user_input['check']:
                    if cache_channel.exists('notifications'):
                        data=cache_channel.hgetall('notifications')

                        return_map=dict()
                        return_map['status']='notifications_available'
                        return_map['count']=len(data)
                        return return_map
                    else:
                        return 'notifications_not_available'

                return_map=dict()
                return_map['notifications']=dict()
                return_map['notifications']['unread']=dict()
                return_map['notifications']['read']=dict()
                self.log.info(f"Checking unread notifications")
                if cache_channel.exists('notifications'):
                    notifications_unread=cache_channel.hgetall('notifications')
                    for k,v in notifications_unread.items():
                        notices=dict()
                        notices[k.decode('utf-8')]=util.ConvertData(v.decode('utf-8')).framework_compatible()
                        return_map['notifications']['unread'].update(notices)
                        return_map['notifications']['unread_count']=len(return_map['notifications']['unread'])
                    self.log.info(f"Checking read notifications")
                notifications_read=cache_channel.keys('notify*')
                if notifications_read:
                    for k in notifications_read:
                        notification=cache_channel.get(k)
                        notices=dict()
                        notices[k.decode('utf-8')]=util.ConvertData(
                            notification.decode('utf-8')).framework_compatible()
                        return_map['notifications']['read'].update(notices)
                        return_map['notifications']['read_count']=len(return_map['notifications']['read'])
                    return return_map

                elif not notifications_read:
                    return_map['count']=len(return_map['notifications'])
                    return return_map
                else:
                    self.log.warning(f"Notifications are not available")
                    return 'notifications_not_available'
            elif method=='POST':
                user_input=kwargs.get('notifications')
                for k,v in user_input['notifications'].items():
                    notification_unread=util.ConvertData(
                        (cache_channel.hget('notifications',k)).decode('utf-8')).framework_compatible()
                    notification_unread['state']=v['state']
                    cache_channel.setex(k,172800,str(notification_unread))
                    cache_channel.hdel('notifications',k)
                if len(user_input['notifications'])>1:
                    return 'notifications_read'
                elif len(user_input['notifications'])<=1:
                    return 'notification_read'
            elif method=='DELETE':
                user_input=kwargs.get('notifications')
                for k,v in user_input['notifications'].items():
                    self.log.info(f"Deleting unread notifications")
                    cache_channel.hdel('notifications',k)
                    self.log.info(f"Deleting read notifications")
                    cache_channel.delete(k)
                if len(user_input['notifications'])>1:
                    return 'notifications_deleted'
                elif len(user_input['notifications'])<=1:
                    return 'notification_deleted'
        finally:
            if cache_channel:
                del cache_channel

    def start_attack(self,cache_channel,db,application_id):
        # cache_channel.hset(application_id, 'cms_application_state', application_status)
        self.log.info(f"Attack initiated for {application_id}")
        cache_channel=self.redis.connect(host=was.was['cache'])
        status=aops.Attack(application_id).initiate()
        # if status=='AppAuth_Session_Failed':
        #     end_time=time.time()
        #     cache_map={'application_id':application_id,'attack_state':'aborted'}
        #     cache_channel.hmset('attack',{application_id:str(cache_map)})

        #     cache_channel.hset(application_id,'attack_state','aborted')
        #     coll=self.mongo.create_collection(db,'applications')
        #     self.mongo.update_document(coll,{
        #         '$set':{'attack.attack_state':"aborted",
        #             'attack.attack_aborted':end_time}},
        #         {'application_id':application_id},upsert=True)
        #     self.mongo.update_document(coll,{'$set':{'detail.state':'aborted'}},
        #         {'application_id':application_id},upsert=True)
        #     return 'AppAuth_Session_Failed'

    # def get_all_application_status(self):
    #     try:
    #         self.log.info(f"Polling for application CMS status started")
    #         status=200
    #         mesg=None
    #         progress=[]
    #         application_status_template={
    #             "id":None,
    #             "state":None
    #         }
    #         cache_channel=self.redis.connect(host=was.was['cache'])
    #         db_channel=self.mongo.connect(host=was.was['database'])
    #         db=self.mongo.create_database(db_channel,'was_db')
    #         coll=self.mongo.create_collection(db,'applications')
    #         db_applications=self.mongo.find_all_documents(coll)
    #         if db_applications=='documents_not_found':
    #             self.log.warning(f"Applications not available in database")
    #             mesg="db_application_not_found"
    #             return (status,mesg)
    #         if not cache_channel.exists('cms'):
    #             self.log.warning(f"CMS is not configured to fetch applications")
    #             mesg="cms_not_configured"
    #             return (status,mesg)
    #         cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
    #         if cache_channel.ttl(cms['username'])<=300:
    #             self.log.warning(f"Regenerating token to connect to CMS")
    #             cms_status=CMS(cms['ipv4_address']).refresh_token(cms['username'])
    #             if 'error' in cms_status:
    #                 mesg="cms_authentication_error"
    #                 return (status,mesg)
    #         user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
    #         cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
    #             cms['ipv4_address'])
    #         cms_applications=CMS(cms['ipv4_address']).applications(cms_services_header)
    #         if (cms_applications is not None) and (cms_applications!="connection_error"):
    #             if not isinstance(cms_applications,list):
    #                 mesg="no_items_from_cms"
    #                 return (status,mesg)
    #             for app in cms_applications:
    #                 application_status_template["id"]=app['id']
    #                 application_status=CMS(cms['ipv4_address']).application_status(app['id'],cms_services_header)
    #                 if application_status=="connection_error":
    #                     mesg="cms_connection_error"
    #                     return (status,mesg)
    #                 db_data=coll.find_one({"detail.id":app['id']})
    #                 if db_data!=None:
    #                     try:
    #                         db_status=db_data["detail"]["state"]
    #                     except KeyError:
    #                         mesg="detail.state_not_found_in_db"
    #                         return (status,mesg)
    #                     ################
    #                     # if not application_status and db_status =="not_configured":
    #                     #     db_status="not_instrumented"
    #                     # # if not application_status and db_status =="not_instrumented":
    #                     # #     pass
    #                     # else:
    #                     if 'crawl' in db_data.keys() and 'payload_policy' in db_data.keys():
    #                         if 'attack' in db_data.keys():
    #                             db_status='report_ready'
    #                         else:
    #                             db_status='attack_ready'

    #                     elif 'payload_policy' in db_data.keys():
    #                         db_status='crawl_ready'
    #                     else:
    #                         db_status="not_configured"
    #                     self.mongo.update_document(coll,{'$set':{'detail.state':db_status}},
    #                         {'application_id':app['id']},upsert=True)

    #                     application_status_template["state"]=db_status
    #                     ####################
    #                     # if application_status:
    #                     #     if db_status =="not_instrumented":
    #                     #         if 'crawl' in db_data.keys() and 'payload_policy' in db_data.keys():
    #                     #             if 'attack' in db_data.keys():
    #                     #                 db_status='report_ready'
    #                     #             else:
    #                     #                 db_status='attack_ready'

    #                     #         elif 'payload_policy' in db_data.keys():
    #                     #             db_status='crawl_ready'
    #                     #         else:
    #                     #             db_status="not_configured"
    #                     #         self.mongo.update_document(coll,{'$set':{'detail.state':db_status}},
    #                     #             {'application_id':app['id']},upsert=True)

    #                     #         application_status_template["state"]=db_status
    #                     # else:
    #                     #     if db_status !="not_instrumented":
    #                     #         self.mongo.update_document(coll,{'$set':{'detail.state':"not_instrumented"}},
    #                     #             {'application_id':app['id']},upsert=True)
    #                     #         db_status="not_instrumented"
    #                     #     application_status_template["state"]=db_status
    #                     progress.append(copy.deepcopy(application_status_template))
    #                 else:
    #                     mesg="appid_not_found_in_db"
    #                     return (status,mesg)
    #             mesg=progress
    #             return (status,mesg)
    #         mesg="cms_app_list_empty"
    #         return (status,mesg)

    #     except Exception as e:
    #         self.log.error(f"Error: Exception: {str(e)}")
    #         mesg="exception"
    #         return (status,mesg)
    #     finally:
    #         self.log.info(f"Polling for application CMS status completed")
    #         if 'cache_channel' in locals():
    #             del cache_channel
    #         if 'db_channel' in locals():
    #             db_channel.close()

    def get_all_application_status(self):
        try:
            self.log.info(f"Polling for application CMS status started")
            status=200
            mesg=None
            progress=[]
            application_status_template={
                "id":None,
                "state":None,
                "instrumentation":None
            }
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'applications')
            db_applications=self.mongo.find_all_documents(coll)
            if db_applications=='documents_not_found':
                self.log.warning(f"Applications not available in database")
                mesg="db_application_not_found"
                return (status,mesg)
            if not cache_channel.exists('cms'):
                self.log.warning(f"CMS is not configured to fetch applications")
                mesg="cms_not_configured"
                return (status,mesg)
            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            if cache_channel.ttl(cms['username'])<=300:
                self.log.warning(f"Regenerating token to connect to CMS")
                cms_status=CMS(cms['ipv4_address']).refresh_token(cms['username'])
                if 'error' in cms_status:
                    mesg="cms_authentication_error"
                    return (status,mesg)
            user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                cms['ipv4_address'])
            cms_applications=CMS(cms['ipv4_address']).applications(cms_services_header)
            if (cms_applications is not None) and (cms_applications!="connection_error"):
                if not isinstance(cms_applications,list):
                    mesg="no_items_from_cms"
                    return (status,mesg)
                for app in cms_applications:
                    application_status_template["id"]=app['id']
                    application_status=CMS(cms['ipv4_address']).application_status(app['id'],cms_services_header)
                    if application_status=="connection_error":
                        mesg="cms_connection_error"
                        return (status,mesg)
                    db_data=coll.find_one({"detail.id":app['id']})
                    if db_data!=None:
                        try:
                            db_intrumentation=db_data["detail"]["instrumentation"]
                            detail_state = db_data["detail"]["state"]
                        except KeyError:
                            mesg="detail.state_not_found_in_db"
                            return (status,mesg)
                        if application_status:
                            if db_intrumentation == True:
                                application_status_template["instrumentation"]= db_intrumentation
                                application_status_template["state"] = detail_state
                            else:
                                application_status_template["instrumentation"]= application_status
                                application_status_template["state"] = detail_state
                                self.mongo.update_document(coll,{'$set':{'detail.instrumentation':True}},
                                    {'application_id':app['id']},upsert=True)
                        else:
                            if db_intrumentation != False:
                                self.mongo.update_document(coll,{'$set':{'detail.instrumentation':False}},
                                    {'application_id':app['id']},upsert=True)
                                db_intrumentation = False
                            application_status_template["instrumentation"]= db_intrumentation
                            application_status_template["state"] = detail_state
                        progress.append(copy.deepcopy(application_status_template))
                    else:
                        mesg="appid_not_found_in_db"
                        return (status,mesg)
                mesg=progress
                return (status,mesg)
            mesg="cms_app_list_empty"
            return (status,mesg)
        except Exception as e:
            self.log.error(f"Error: Exception: {str(e)}")
            mesg="exception"
            return (status,mesg)
        finally:
            self.log.info(f"Polling for application CMS status completed")
            if 'cache_channel' in locals():
                del cache_channel
            if 'db_channel' in locals():
                db_channel.close()

    def clear_application_data(self,method,application_id):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            if method=='DELETE':
                db_states=set()

                cache_channel=self.redis.connect(host=was.was['cache'])
                self.log.info(f"Deleting URL store from application {application_id}")
                coll=self.mongo.create_collection(db,'url_store')
                status=self.mongo.delete_document(coll,{'application_id':application_id})

                coll1=self.mongo.create_collection(db,'pre_crawl_store')
                status=self.mongo.delete_document(coll1,{'application_id':application_id})

                coll=self.mongo.create_collection(db,'applications')
                self.log.info(f"Checking if application has crawled any user {application_id}")

                current_application=self.mongo.find_document(coll,{'application_id':application_id})
                if 'crawl' in current_application:
                    self.log.info(f"Deleting crawl from application")
                    del current_application['crawl']
                    if cache_channel.exists('crawl'):
                        cache_channel.hdel('crawl',application_id)

                self.log.info(f"Checking if application has attacked any user {application_id}")

                if 'attack' in current_application:
                    self.log.info(f"Deleting attack from application")
                    del current_application['attack']
                    if cache_channel.exists('attack'):
                        cache_channel.hdel('attack',application_id)

                self.log.info(f"Application data deleted sucessfully")
                if 'payload_policy' in current_application:
                    del current_application['payload_policy']
                    if cache_channel.exists('payload_policy'):
                        cache_channel.hdel('payload_policy',application_id)

                cache_channel.hset(application_id,'manual_pre_crawl','not_configured')
                cache_channel.hset(application_id,'homepage_url','not_configured')
                cache_channel.hset(application_id,'framework_authentication','not_configured')
                cache_channel.hset(application_id,'application_authentication','not_configured')
                cache_channel.hset(application_id,'payload_policy','not_configured')

                status=self.mongo.delete_document(coll,{'application_id':application_id})
                db_states.add(status)
                return 'application_data_reseted'

        finally:
            if db_channel:
                db_channel.close()
                
    def cms_application_status(self, application_id):
        try:
            # <----- Validate the Application in Mongodb ----->
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')

            self.log.info(f"Querying database for applications")
            coll=self.mongo.create_collection(db,'applications')
            doc= self.mongo.find_document(coll,{'application_id':application_id})
            if not isinstance(doc,dict):
                self.log.warning(f"Applications not available in database")
                # return 'invalid_application_id'
                return {'status':"invalid_application_id", "message":'Applications not available in Was database'}
            
            # <----- Application status from CMS ----->
            
            self.log.info(f"Checking token expiry status")
            if cache_channel.exists('cms'):
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            else:
                self.log.critical(f"CMS is not configured to fetch applications")
                # return 'cms_not_configured'
                return {'status':"cms_not_configured", "message":'CMS is not configured to fetch applications'}
            self.log.warning(f"CMS token will expire in {cache_channel.ttl(cms['username'])} seconds")
            if cache_channel.ttl(cms['username'])>300:
                self.log.info(f"Using existing token to connect to CMS")
                user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            else:
                self.log.warning(f"Regenerating token to connect to CMS")
                status=CMS(cms['ipv4_address']).refresh_token(cms['username'])

                if status=='success':
                    self.log.info(f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                    user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                elif 'error' in status:
                    if 'captcha' in status['error_description']:
                        # return 'cms_captcha_error'
                        return {'status':"cms_captcha_error", "message":'CMS captcha error'}
                    
                    else:
                        # return 'cms_authentication_error'
                        return {'status':"cms_authentication_error", "message":'CMS authentication error'}
                    
            self.log.info(f"Querying CMS for applications")
            cms_services_header=util.Authentication().create_http_header('services',user['access_token'],
                cms['ipv4_address'])
            
            status=CMS(cms['ipv4_address']).application_status(application_id, cms_services_header)
            
            # <----- To Update cms Status on Application ----->
            # if doc['detail']['instrumentation'] != status:
            #     try:
            #         db_channel=self.mongo.connect(host=was.was['database'])
            #         db=self.mongo.create_database(db_channel,'was_db')
            #         coll=self.mongo.create_collection(db,'applications')
            #         doc=self.mongo.update_document(coll,{'$set':{'detail.instrumentation':status}},
            #                     {'application_id':application_id},upsert=True)
            #         if doc == 'sucess':
            #             self.log.info(f"Instrumentation status updated Sucessfully{application_id}")
            #     except Exception as e:
            #         self.log.warning(f"Instrumentation status updated Unsucessful {application_id}")
            
            if status != None:
                return {'status':'success', "message":{'application_id':application_id,
                                                   'instrumentation':status}}
            else:
                return {'status':'failure', "message":"Status API does not return valid response"}
            
        except Exception as e:
            return {'status':'failure', "message":str(e)} 
        finally:
            if db_channel:
                db_channel.close()


class CMS:

    def __init__(self,address):
        self.address=address
        self.log=util.Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()
        self.cms_vm_username=None
        self.cms_vm_password=None
        self.ae_vm_username=None
        self.ae_vm_password=None
        self.ae_log_path=None
        #self.app_non_instrument_time = set()

    def token_validity(self,username):
        try:
            self.log.info(f"Checking CMS bearer token validity")
            cache_channel=self.redis.connect(host=was.was['cache'])
            token_timeout=cache_channel.get('cms_bearer_token')
            if token_timeout<60:
                self.log.warning(f"CMS bearer token expiring in {token_timeout} seconds")
                return 'expiring'
            else:
                self.log.info(f"CMS bearer token is valid until {token_timeout} seconds")
                return 'valid'
        finally:
            if cache_channel:
                del cache_channel

    def login(self,username,password,header):
        url=api.CMS(self.address).login()
        data=payload.CMS().login(username,password)

        self.log.info(f"Login to CMS {self.address}")
        response=util.Connect().HTTP(url,header,data).add()
        return response

    def token_status(self):
        cache_channel=self.redis.connect(host=was.was['cache'])
        db_channel=self.mongo.connect(host=was.was['database'])
        #'was_db'=was.environment["current_db"]
        db=self.mongo.create_database(db_channel,'was_db')

        self.log.info(f"Checking token expiry status")
        if cache_channel.exists('cms'):
            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
        else:
            self.log.critical(f"CMS is not configured to fetch applications")
            return 'cms_not_configured'
        self.log.warning(f"CMS token will expire in {cache_channel.ttl(cms['username'])} seconds")
        if cache_channel.ttl(cms['username'])>300:
            self.log.info(f"Using existing token to connect to CMS")
            user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
            return user['access_token']
        else:
            self.log.warning(f"Regenerating token to connect to CMS")
            status=CMS(cms['ipv4_address']).refresh_token(cms['username'])

            if status=='success':
                self.log.info(f"Regenerated token is valid for {(cache_channel.ttl(cms['username']))} seconds")
                user=util.ConvertData((cache_channel.get(cms['username'])).decode('utf-8')).framework_compatible()
                return user['access_token']
            elif 'error' in status:
                if 'captcha' in status['error_description']:
                    return 'cms_captcha_error'
                else:
                    return 'cms_authentication_error'

    def refresh_token(self,username):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            coll=self.mongo.create_collection(db,'vault')
            doc=self.mongo.find_document(coll,{'username':username,'type':'cms'})
            authentication_header=util.Authentication().create_http_header('authentication',
                cms.cms['authorization_token'],
                self.address)
            self.log.debug(f"Re-login to CMS: {self.address}")
            decrypted_password=util.Authentication().decrypt_password(doc['key'],doc['password'])
            login_detail=CMS(self.address).login(username=doc['username'],password=decrypted_password,
                header=authentication_header)
            if 'error' not in login_detail:
                self.log.info(f"Updating cache with CMS user details")
                cache_map=dict()
                cache_map['username']=doc['username']
                cache_map['user_id']=login_detail['additionalDetails']['userId']
                cache_map['type']='cms'
                cache_map['access_token']=login_detail['access_token']
                cache_map['refresh_token']=login_detail['refresh_token']
                status=cache_channel.setex(doc['username'],login_detail['expires_in'],str(cache_map))
                if status is True:
                    self.log.info(f"CMS bearer token refreshed successfully")
                    return 'success'
                else:
                    return 'failure'
            else:
                self.log.critical(f"CMS login status: {login_detail}")
                return login_detail

        finally:
            pass

    def logout(self,header):
        try:
            url=api.CMS(self.address).logout()
            data=payload.CMS().logout()

            self.log.info(f"Logout from CMS")
            response=util.Connect().HTTP(url,header,data).add()
            if response is not None:
                return response['status']
            else:
                return None
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def applications(self,header):
        try:
            url=api.CMS(self.address).applications()
            data=payload.CMS().applications()

            self.log.info(f"Fetching CMS applications")
            response=util.Connect().HTTP(url,header,data).get()
            if response is not None:
                if response['status']=='success':
                    self.log.info(f"Applications available {response['items']}")
                    return response['items']
                else:
                    self.log.info(f"Applications unavailable")
                    return response
            else:
                return None
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_status(self,application_id,header):
        try:
            status_list=[]
            url=api.CMS(self.address).application_status()
            data=payload.CMS().application_status(application_id)

            self.log.info(f"Fetching application status of {application_id}")
            response=util.Connect.HTTP(url,header,data).add()
            if response is not None:
                if response['status']=='success':
                    apps=response.get('item',{}).get('data',{}).get('dataset',None)
                    if apps is None:
                        self.log.critical(f"Application API does not have item->data->dataset key")
                        return None
                    for app in apps:
                        status_count=app.get('detail',{}).get('applications',[{'count':None}])[0]['count']
                        if status_count is None:
                            self.log.critical(f"Application API does not have applications->count")
                            return None
                        if status_count>=1:
                            self.log.info(f"Application status of {application_id}: {app['status']}")
                            status_list.append(app['status'])

                    if len(list(filter(lambda i:i.lower() in was.was["CMS"]["acceptable_app_status"],status_list)))>0:
                        return True
                    return False
                else:
                    self.log.critical(f"Application status: {response['status']}")
                    return None
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_services(self,application_id,header):
        try:
            url=api.CMS(self.address).application_services(application_id)
            data=payload.CMS().application_services()
            self.log.info(f"Fetching services for application {application_id}")

            response=util.Connect.HTTP(url,header,data).get()
            if response is not None:
                if 'status' in response:
                    if response['status']=='success':
                        return response['item']
                    else:
                        self.log.critical(f"Application status: {response['status']}")
                        return None
                elif 'Invalid Application' in response['messages']:
                    self.log.critical(f"Application status: {response['status']}")
                    return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_analysis_engine(self,application_id,header):
        try:
            url=api.CMS(self.address).application_analysis_engine(application_id)
            data=payload.CMS().application_analysis_engine()
            self.log.info(f"Fetching services for application {application_id}")

            response=util.Connect.HTTP(url,header,data).get()
            if response is not None:
                if 'status' in response:
                    if response['status']=='success':
                        return response['item']
                    else:
                        self.log.critical(f"Application status: {response['status']}")
                        return None
                elif 'Invalid Application' in response['messages']:
                    self.log.critical(f"Application status: {response['status']}")
                    return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_instances(self,application_id,header):
        try:
            url=api.CMS(self.address).application_instances(application_id)
            data=payload.CMS().application_services()
            self.log.info(f"Fetching instances for application {application_id}")
            response=util.Connect.HTTP(url,header,data).get()
            if response is not None:
                if 'status' in response:
                    if response['status']=='success':
                        return response['item']
                    else:
                        self.log.critical(f"Application status: {response['status']}")
                        return None
                elif 'Invalid Application' in response['messages']:
                    self.log.critical(f"Application status: {response['status']}")
                    return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_incidents(self,application_id,header):
        try:
            url=api.CMS(self.address).get_all_incidents()
            data=payload.CMS().get_all_incidents()
            self.log.info(f"Fetching incidents for application {application_id}")
            response=util.Connect.HTTP(url,header,data).get()
            if response is not None:
                if 'status' in response:
                    if response['status']=='success':
                        return response['item']['incidents']
                    else:
                        self.log.critical(f"Application status: {response['status']}")
                        return None
                elif 'Invalid Application' in response['messages']:
                    self.log.critical(f"Application status: {response['status']}")
                    return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_incident_detail(self,application_id,header,incident_id,return_empty_response=False):
        try:
            url=api.CMS(self.address).get_incident_details(incident_id=incident_id)
            data=payload.CMS().get_incident_details()
            self.log.info(f"Fetching incidents for application {application_id}")
            response=util.Connect.HTTP(url,header,data).get(return_empty_response)
            ##### CMS_TOKEN##########
            if isinstance(response,requests.Response):
                if response.status_code==401:
                    if "invalid_token" in response.text:
                        self.log.error(f"CMS Token Expired when fetching CMS incidents. Content: {response.text}")
                        return "cms_token_expired"
                    self.log.error(f"CMS returned 401.Status:{response.status_code} Content: {response.text}")
                    return "cms_401"
                if response.status_code==503:
                    return "cms_no_data"
                else:
                    self.log.error(f"CMS not returned 200.Status:{response.status_code} Content: {response.text}")
                    return "cms_fetch_error"
            if isinstance(response,dict):
                if response is not None:
                    if 'status' in response:
                        if response['status']=='success':
                            return response['item']
                        else:
                            self.log.critical(f"Application status: {response['status']}")
                            return None
                    elif ("messages" in response and 'Invalid Application' in response['messages']) or\
                            ("message" in response and 'Invalid Application' in response['message']):
                        self.log.critical(f"Application status: Invalid Application")
                        return 'invalid_application'
                    elif ("messages" in response and 'internal server error' in response['messages']) or\
                            ("message" in response and 'internal server error' in response['message']):
                        # if not self.check_cms_value(application_id=application_id,app_name=""):
                        #     return "CMS_DOWN"
                        self.log.critical(f"Application status: CMS internal server error")
                        return 'cms_no_data'
            if isinstance(response,str):
                self.log.error(f"CMS fetch application details returned: {response}")
                return response
            #############
            # if response is not None:
            #     if 'status' in response:
            #         if response['status'] == 'success':
            #             return response['item']
            #         else:
            #             self.log.critical(f"Application status: {response['status']}")
            #             return None
            #     elif 'Invalid Application' in response['messages']:
            #         self.log.critical(f"Application status: {response['status']}")
            #         return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def application_incidents_all(self,application_id,header,return_empty_response=False):
        try:
            def get_data_from_cms(body):
                url=api.CMS(self.address).search_application_details()
                data=payload.CMS().search_application_details(body)
                self.log.info(f"Fetching incidents for application {application_id}")
                response=util.Connect.HTTP(
                    url=url,
                    header=header,
                    payload=data).post(return_empty_response)
                return response

            incidents_list=[]
            bNext=True
            page_counter=1
            while bNext:
                #sleep(1)
                #if self.check_cms_value(application_id=application_id,app_name=""):
                body_template={
                    "expression":{
                        "relation":"AND",
                        "criteriaList":[
                            {
                                "operator":"IN",
                                "ignoreCase":False,
                                "field":"appId",
                                "value":None,
                                "values":[application_id],
                                "oid":False
                            }
                        ],
                        "expressionList":[]
                    },
                    "sort":{
                        "sortItems":[
                            {
                                "key":"type",
                                "direction":"DESC"
                            }
                        ]
                    },
                    "page":{
                        "page":page_counter,
                        "size":"100"
                    },
                    "collation":None
                }
                response=get_data_from_cms(body_template)
                if isinstance(response,requests.Response):
                    if response.status_code==401:
                        del incidents_list
                        if "invalid_token" in response.text:
                            self.log.error(
                                f"CMS Token Expired when fetching CMS incidents. Content: {response.text}")
                            return "cms_token_expired"
                        self.log.error(f"CMS returned 401.Status:{response.status_code} Content: {response.text}")
                        return "cms_401"
                    else:
                        self.log.error(
                            f"CMS not returned 200.Status:{response.status_code} Content: {response.text}")
                        return "cms_fetch_error"
                if isinstance(response,dict):
                    if 'status' in response:
                        if response['status']=='SUCCESSFUL':
                            if (len(response['items'])==0):
                                bNext=False
                            # if not self.check_cms_value(application_id=application_id,app_name=""):
                            #     return False
                            incidents_list.extend(response['items'])
                            page_counter+=1
                        else:
                            self.log.critical(f"Application status: {response['status']}")
                            return None
                    elif 'Invalid Application' in response['messages']:
                        self.log.critical(f"Application status: {response['status']}")
                        return 'invalid_application'
                if isinstance(response,str):
                    self.log.error(f"CMS fetch application details returned: {response}")
                    return response
                # else:
                #     return False
            return incidents_list
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def pool_CMS_status(self,application_id):
        try:
            current_app_status = ""
            cache_channel=self.redis.connect(host=was.was['cache'])
            bPoolCMS=True
            self.log.info(f"CMS Heartbeat functionality started; App ID: {application_id}")
            while bPoolCMS:
                self.log.info(f"Checking token expiry status")
                if cache_channel.exists('cms'):
                    cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                else:
                    self.log.critical(f"CMS is not configured to fetch applications")
                    return 'cms_not_configured'

                access_token=self.token_status()  #what to do when token expires?
                if access_token not in ["cms_not_configured","cms_captcha_error","cms_authentication_error",
                    "decode_error"]:
                    self.log.info(f"Querying CMS for application {application_id}")
                    cms_services_header=util.Authentication().create_http_header('services',access_token,
                        cms['ipv4_address'])
                    if cms_services_header!="exception":
                        application_status=self.application_status(application_id,cms_services_header)
                        
                        self.log.info(
                            f"CMS Heartbeat:  Application status on CMS for {application_id} found as {application_status}")
                        
                        if not isinstance(current_app_status,str):
                            if current_app_status != application_status:
                                if not application_status:
                                    self.capture_noninstrumented_time(application_id)
                                    
                                else:
                                    self.capture_instrumented_time(application_id)
                                
                                current_app_status= application_status 
                        else:
                            if not application_status:
                                self.capture_noninstrumented_time(application_id)
                           
                            current_app_status= application_status 
                            
                        if not application_status:
                            cache_channel.hset(application_id,"cms_pool_status",str({"pool_status":"CMS_NOT_OK"}))
                            #bPoolCMS=False
                            #self.capture_noninstrumented_time(application_id)
                            self.log.info(
                                f"CMS Heartbeat:  For {application_id} state found {application_status} Stopping heartbeat function for CMS")
                        # else:
                        #     cache_channel.hset(application_id,"cms_pool_status",str({"pool_status":"CMS_OK"}))
                        #     #self.capture_instrumented_time(application_id)
                        #     self.log.info(
                        #         f"CMS Heartbeat:  For {application_id} state found {application_status}")
                       
                            
                        attack_status=util.ConvertData(
                            cache_channel.hget(application_id,"attack_status").decode('utf-8')).framework_compatible()
                        if attack_status["attack_status"]=="ATTACK_DONE":
                            self.log.info(
                                f"CMS Heartbeat:  For {application_id} attack completed; Stopping heartbeat function for CMS")
                            bPoolCMS=False
                else:
                    self.log.critical(f"CMS Heartbeat Exception! Error fetching CMS token :{access_token}")
                    cache_channel.hset(application_id,"cms_pool_status",str({"pool_status":"CMS_NOT_OK"}))
                    bPoolCMS=False
                    return None
        except Exception as e:
            self.log.critical(f"CMS Heartbeat Exception! Exception raised: {e}")
            cache_channel.hset(application_id,"cms_pool_status",str({"pool_status":"CMS_NOT_OK"}))
            return None
        finally:
            self.log.info(f"CMS Heartbeat functionality completed; App ID: {application_id}")

    def capture_noninstrumented_time(self,application_id):
        cache_channel=self.redis.connect(host=was.was['cache'])
        # utc_now = datetime.now(tz=pytz.UTC)
        # local_zone = tz.tzlocal()
        # local_now = utc_now.astimezone(local_zone)
        #dtobj = datetime.now(tz=gettz('Asia/Kolkata'))
        dtobj= time.time()
        if cache_channel.hexists(application_id,'not_instrumented'):
            not_instrumented=util.ConvertData(
                (cache_channel.hget(application_id,'not_instrumented')).decode('utf-8')).framework_compatible()
            
            #set_status=str(not_instrumented)+"#"+str(dtobj)
            #set_status=f"{str(not_instrumented)}#{str(dtobj.strftime('%Y-%m-%d, %H.%M.%S'))} IST"#"+str(dtobj)
            set_status = f"{str(not_instrumented)}#{str(dtobj)}"
            cache_channel.hset(application_id,'not_instrumented',set_status)
        else:
            set_status=f"{str(dtobj)}"
            cache_channel.hset(application_id,'not_instrumented',str(set_status))
            
    def capture_instrumented_time(self,application_id):
        cache_channel=self.redis.connect(host=was.was['cache'])
        dtobj= time.time()
        if cache_channel.hexists(application_id,'instrumented'):
            instrumented=util.ConvertData(
                (cache_channel.hget(application_id,'instrumented')).decode('utf-8')).framework_compatible()
    
            set_status = f"{str(instrumented)}#{str(dtobj)}"
            cache_channel.hset(application_id,'instrumented',set_status)
            
        else:
            set_status=f"{str(dtobj)}"
            cache_channel.hset(application_id,'instrumented',str(set_status))
            
    def application_details_from_archived(self,header,application_id,start_time=0,end_time=0,counter=0):
        try:
            endpoint=api.CMS(self.address).search_archived_details_for_application(application_id)
            bNext=True
            incidents_list=[]
            page_counter=1
            size=100
            self.log.info(
                f"App: {application_id} was not in Normal/Attack/Threat state; Switching to fetch details from archive")
            while bNext:
                if start_time!=0 and end_time!=0:
                    url=f"{endpoint}&page={page_counter}&size={size}&sort=timestamp&order=desc&from={start_time}&to={end_time}"
                else:
                    url=f"{endpoint}&page={page_counter}&size={size}&sort=timestamp&order=desc"
                self.log.info(f"Fetching incidents for application {application_id} from archive")
                response=util.Connect.HTTP(
                    url=url,
                    header=header).get()
                if isinstance(response,requests.Response):
                    if response.status_code==401:
                        if "invalid_token" in response.text:
                            self.log.error(f"CMS Token Expired when fetching CMS incidents. Content: {response.text}")
                            return "cms_token_expired"
                        self.log.error(f"CMS returned 401.Status:{response.status_code} Content: {response.text}")
                        return "cms_401"
                    else:
                        self.log.error(f"CMS not returned 200.Status:{response.status_code} Content: {response.text}")
                        return "cms_fetch_error"
                if isinstance(response,dict):
                    if 'status' in response:
                        if response['status'].lower()=='success':
                            if (len(response['item']['incidents'])==0):
                                """30 counter to wait for data to populate as incidents does not get populated at archive side 
                                immediately after unprovisioning"""
                                if page_counter==1 and counter<=30: 
                                    #sleep(1)
                                    return self.application_details_from_archived(
                                        header=header,application_id=application_id,
                                        start_time=start_time,end_time=end_time,
                                        counter=counter+1)
                                bNext=False
                            incidents_list.extend(response['item']['incidents'])
                            page_counter+=1
                        else:
                            self.log.critical(f"Application status: {response['status']}")
                            return None
                    elif ('messages' in response and 'Invalid Application' in response['messages']) or\
                            ('message' in response and 'Invalid Application' in response['message']):
                        self.log.critical(f"Application status: {response['status']}")
                        return 'invalid_application'
                    else:
                        self.log.critical(f"CMS returned: {str(response)}")
                        return "internal_server_error"
                if isinstance(response,str):
                    self.log.error(f"CMS fetch application details returned: {response}")
                    return response
            return incidents_list
        except Exception as e:
            self.log.error(f"Exception raised: {e}")
            return "exception"

    def application_archived_incident_detail(self,application_id,header,incident_id,return_empty_response=False,
                                             counter=0):
        try:
            url=api.CMS(self.address).get_archived_incident_details(incident_id=incident_id)
            data=payload.CMS().get_incident_details()
            self.log.info(f"Fetching incidents for application {application_id}")
            response=util.Connect.HTTP(url,header,data).get(return_empty_response)
            ##### CMS_TOKEN##########
            if isinstance(response,requests.Response):
                if response.status_code==401:
                    if "invalid_token" in response.text:
                        self.log.error(f"CMS Token Expired when fetching CMS incidents. Content: {response.text}")
                        return "cms_token_expired"
                    self.log.error(f"CMS returned 401.Status:{response.status_code} Content: {response.text}")
                    return "cms_401"
                if response.status_code==503:
                    return "cms_no_data"
                else:
                    self.log.error(f"CMS not returned 200.Status:{response.status_code} Content: {response.text}")
                    return "cms_fetch_error"
            if isinstance(response,dict):
                if response is not None:
                    if 'status' in response:
                        if response['status']=='success':
                            if "internal_server_error" in response['item']:
                                self.log.critical(f"Archived CMS returned: {response['item']}")
                                return "internal_server_error"
                            return response['item']
                        else:
                            self.log.critical(f"Application status: {response['status']}")
                            return None
                    elif ('messages' in response and 'Invalid Application' in response['messages']) or\
                            ('message' in response and 'Invalid Application' in response['message']):
                        self.log.critical(f"Application status: {response}")
                        return 'invalid_application'
                    elif ('messages' in response and 'internal server error' in response['messages']) or\
                            ('message' in response and 'internal server error' in response['message']):
                        if counter<=30:
                            #sleep(1)
                            return self.application_archived_incident_detail(
                                application_id=application_id,
                                header=header,
                                incident_id=incident_id,
                                return_empty_response=return_empty_response,
                                counter=counter+1)
                        else:
                            self.log.critical(f"CMS returned: {str(response)}")
                            return "cms_no_data"
                    else:
                        self.log.critical(f"CMS returned: {str(response)}")
                        return "internal_server_error"
            if isinstance(response,str):
                self.log.error(f"CMS fetch application details returned: {response}")
                return response
            #############
            # if response is not None:
            #     if 'status' in response:
            #         if response['status'] == 'success':
            #             return response['item']
            #         else:
            #             self.log.critical(f"Application status: {response['status']}")
            #             return None
            #     elif 'Invalid Application' in response['messages']:
            #         self.log.critical(f"Application status: {response['status']}")
            #         return 'invalid_application'
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'

    def check_cms_value(self,application_id,app_name):
        cache_channel=self.redis.connect(host=was.was['cache'])
        cms_pool_status=util.ConvertData(
            cache_channel.hget(application_id,"cms_pool_status").decode('utf-8')).framework_compatible()
        if cms_pool_status["pool_status"].upper()=="CMS_OK":
            return True
        return False

    def cms_version_check(self,header):
        try:
            url=api.CMS(self.address).cms_version()
            #data = payload.CMS().cms_version()

            self.log.info(f"Fetching CMS Version info")
            response=util.Connect().HTTP(url,header).get()
            if response is not None:
                if response['status']=='success':
                    self.log.info(f"CMS version {response['item']}")
                    return response['item']
                else:
                    self.log.info(f"CMS version info not Available")
                    return response
            else:
                return None
        except ConnectionError as err:
            self.log.error(err)
            return 'connection_error'
    
    def generate_cms_vm_login_info(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            coll_vault=self.mongo.create_collection(db,'vault')
            coll_config=self.mongo.create_collection(db,'configuration')
            config=self.mongo.find_document(coll_config,{'api_version':'1.0'})
            if isinstance(config,str) and  config in ["document_not_found","connection_error"]:
                self.log.error(f"Report: CMS Configuration not found/unable to connect to DB: {config}")
                return False
            vm_username=config.get("cms",{}).get(cms['ipv4_address'].replace(".","_"),{}).get("vm_username",None)
            if vm_username is not None:
                self.cms_vm_username=vm_username
                vault=self.mongo.find_document(coll_vault,{'ipv4_address':cms['ipv4_address'],"type":"vm_password"})
                if isinstance(vault,str) and vault in ["document_not_found","connection_error"]:
                    self.log.error(f"Report: CMS Configuration password not found/unable to connect to DB: {config}")
                    return False
                cms_password=util.Authentication().decrypt_password(key=vault['key'],encrypted_password=vault['password'])
                if cms_password != "value_error":
                    self.cms_vm_password=cms_password
                    return True
                self.log.error("Report: Error generating CMS password/not found")
                return False
            self.log.error("Report: CMS username not found")
            return False
        except Exception as e:
            self.log.error(f"Report: Exception {e}")
            return False
        finally:
            if "db_channel" in locals():
                db_channel.close()
                
    def generate_ae_vm_login_info(self,cms_ip,application_ae_address):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            Ae_config = self.mongo.create_collection(db,'configuration')
            doc=self.mongo.find_document(Ae_config,{'api_version':'1.0'})
            if isinstance(doc,str) and  doc in ["document_not_found","connection_error"]:
                self.log.error(f"Report: AE Configuration not found/unable to connect to DB: {doc}")
                return False
            ae_config=doc.get("cms",{}).get(cms_ip.replace(".","_"),{}).get("ae",[])
            if len(ae_config) == 0:
                self.log.error("Report generation exited early; AE configaration not found")
                return False 
            ae_username=ae_config[0].get(application_ae_address.replace(".","_"),{}).get("user_name",None)
            if ae_username is not None:
                self.ae_vm_username=ae_username
                log_path=ae_config[0].get(application_ae_address.replace(".","_"),{}).get("log_path","")
                self.ae_log_path=log_path if log_path != "" else f"/var/virsec/log/emejson.log"
                coll_vault=self.mongo.create_collection(db,'vault')
                vault=self.mongo.find_document(coll_vault,{'ipv4_address':application_ae_address,"type":"ae"})
                if isinstance(vault,str) and  vault in ["document_not_found","connection_error"]:
                    self.log.error(f"Report: AE Configuration password not found/unable to connect to DB: {vault}")
                    return False
                ae_password=util.Authentication().decrypt_password(key=vault['key'],encrypted_password=vault['password'])
                if ae_password != "value_error":
                    self.ae_vm_password=ae_password
                    return True
                self.log.error("Report: Error generating CMS password/not found")
                return False
            return False
            
        except Exception as e:
            self.log.error(f"Report: Exception {e}")
            return False
        finally:
            if "db_channel" in locals():
                db_channel.close()
