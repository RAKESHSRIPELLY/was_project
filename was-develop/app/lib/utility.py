__author__='JG'

import logging
import time
from logging.handlers import SysLogHandler,SocketHandler
import redis_log_handler
from redis_log_handler import RedisKeyHandler
import socket
import traceback
import secrets
import uuid
from passlib import hash
from cryptography.fernet import Fernet
import random
import string
import urllib3
import requests
from requests.auth import HTTPDigestAuth
from requests_ntlm import HttpNtlmAuth
import paramiko
from scp import SCPClient
from pypsexec.client import Client
import winrm
from redis import Redis,RedisError
from pymongo import MongoClient,errors
from base64 import b64encode
import profile
import pstats
import shutil
from json import load,loads,dump,dumps,decoder,JSONDecodeError
from flask import request
import xmltodict
from xml.etree import ElementTree as ET
import os
from config import was,environment as env
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
import smtplib
import ssl
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from abc import ABCMeta,abstractmethod


class Log_Main(metaclass=ABCMeta):
    @abstractmethod
    def get_instance(self): raise NotImplemented

    @abstractmethod
    def critical(self): raise NotImplemented

    @abstractmethod
    def error(self): raise NotImplemented

    @abstractmethod
    def warning(self): raise NotImplemented

    @abstractmethod
    def info(self): raise NotImplemented

    @abstractmethod
    def debug(self): raise NotImplemented


class Log(Log_Main):
    __logger=None
    __handler=None

    @staticmethod
    def get_instance():
        if Log.__logger==None:
            Log()
        return Log.__logger

    def __del__(self):
        try:
            if Log.__handler!=None:
                Log.__handler.close()
        except:
            pass

    def __init__(self,level=logging.DEBUG,filename=None):
        if Log.__logger==None:
            max_size=(int(was.environment["logging"]["execution_log"]["size_limit"])*1024*1024)
            backup_count=int(was.environment["logging"]["execution_log"]["backup_count"])
            if filename is None:
                filename=os.path.join(was.environment["logging"]["log_location"],
                    was.environment["logging"]["execution_log"]["name"])
            logger=logging.getLogger(__name__)
            rotate_handler=logging.handlers.RotatingFileHandler(filename,maxBytes=max_size,backupCount=backup_count,
                mode='a')
            logger.setLevel(level)
            formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            rotate_handler.setFormatter(formatter)
            logger.addHandler(rotate_handler)
            Log.__logger=logger
            Log.__handler=rotate_handler

    # def log(self, text, level, notify=False):

    #     logger=self.get_instance()
    #     #logger = logging.getLogger(__name__)

    #     # rotate_handler = logging.handlers.RotatingFileHandler(f"{env.workspace}/artefacts/traces/execution.log",
    #     #                                                       maxBytes=250, backupCount=2)
    #     # rotate_handler.setLevel(logging.INFO)
    #     # logger.addHandler(rotate_handler)

    #     # file_handler = logging.handlers.WatchedFileHandler(f"{env.workspace}/artefacts/traces/execution.log")
    #     # logger.setLevel(logging.INFO)
    #     # logger.addHandler(file_handler)

    #     if level.lower() == 'critical':
    #         logger.critical(text, exc_info=True)
    #     elif level.lower() == 'errors':
    #         logger.error(text, exc_info=True)
    #     elif level.lower == 'warning':
    #         logger.warning(text)
    #     elif level.lower() == 'info':
    #         logger.info(text)
    #     elif level.lower() == 'debug':
    #         logger.debug(text)
    #     print(text)

    # def log(self, text, level, notify=False):

    #     logger = logging.getLogger(__name__)
    #     execution_log=os.path.join(was.environment["logging"]["log_location"],was.environment["logging"]["execution_log"]["name"])
    #     max_size=(int(was.environment["logging"]["execution_log"]["size_limit"]) * 1024 * 1024)
    #     backup_count=int(was.environment["logging"]["execution_log"]["backup_count"])
    #     rotate_handler = logging.handlers.RotatingFileHandler(execution_log,maxBytes=max_size, backupCount=backup_count,mode='a')
    #     logger.setLevel(logging.DEBUG)
    #     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #     rotate_handler.setFormatter(formatter)
    #     logger.addHandler(rotate_handler)

    #     if level.lower() == 'critical':
    #         logger.critical(text, exc_info=True)
    #     elif level.lower() == 'errors':
    #         logger.error(text, exc_info=True)
    #     elif level.lower == 'warning':
    #         logger.warning(text)
    #     elif level.lower() == 'info':
    #         logger.info(text)
    #     elif level.lower() == 'debug':
    #         logger.debug(text)
    #     print(text)

    def critical(self,text,notify=False):
        logger=self.get_instance()
        logger.critical(text,exc_info=True)
        #self.log(text, 'critical', notify=notify)

    def error(self,text,notify=False):
        logger=self.get_instance()
        logger.error(text,exc_info=True)
        #self.log(text, 'errors', notify=notify)

    def warning(self,text,notify=False):
        logger=self.get_instance()
        logger.warning(text)
        #self.log(text, 'warning', notify=notify)

    def info(self,text,notify=False):
        logger=self.get_instance()
        logger.info(text)
        #self.log(text, 'info', notify=notify)

    def debug(self,text,notify=False):
        logger=self.get_instance()
        logger.debug(text)
        #self.log(text, 'debug', notify=notify)


class Crawl_Log(Log_Main):
    __logger=None

    @staticmethod
    def get_instance():
        if Crawl_Log.__logger==None:
            Crawl_Log()
        return Crawl_Log.__logger

    def __init__(self,level=was.environment["logging"]["level"],filename=None):
        if Crawl_Log.__logger==None:
            max_size=(int(was.environment["logging"]["crawl_log"]["size_limit"])*1024*1024)
            backup_count=int(was.environment["logging"]["crawl_log"]["backup_count"])
            if filename is None:
                filename=os.path.join(was.environment["logging"]["log_location"],
                    was.environment["logging"]["crawl_log"]["name"])
            logger=logging.getLogger(__name__)
            rotate_handler=logging.handlers.RotatingFileHandler(filename,maxBytes=max_size,backupCount=backup_count,
                mode='a')
            logger.setLevel(level)
            formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            rotate_handler.setFormatter(formatter)
            logger.addHandler(rotate_handler)
            Crawl_Log.__logger=logger

    def critical(self,text,notify=False):
        logger=self.get_instance()
        logger.critical(text,exc_info=True)

    def error(self,text,notify=False):
        logger=self.get_instance()
        logger.error(text,exc_info=True)

    def warning(self,text,notify=False):
        logger=self.get_instance()
        logger.warning(text)

    def info(self,text,notify=False):
        logger=self.get_instance()
        logger.info(text)

    def debug(self,text,notify=False):
        logger=self.get_instance()
        logger.debug(text)


class Network:

    def __init__(self):
        self.log=Log()

    def get_hostname(self):
        try:
            hostname=socket.gethostname()
            self.log.info(f"Hostname of this machine is- {hostname}")
            return hostname
        except socket.error as err:
            self.log.error(err)
            traceback.print_exc(err)
            return 'socket_error'

    def get_ipv4(self,dns='4.2.2.2',port=80):
        try:
            conx=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            conx.connect((dns,port))
            ipv4=conx.getsockname()[0]
            self.log.info(f"IPv4 address of WAS application: {ipv4}")
            return ipv4
        except socket.error as err:
            self.log.error(err)
            traceback.print_exc(err)
            return 'socket_error'
        finally:
            conx.close()

    def get_ipv4_by_hostname(self,hostname):
        try:
            ipv4=socket.gethostbyname(hostname)
            self.log.info(f"IPv4 for {hostname} is- {ipv4}")
            return ipv4
        except socket.error as err:
            self.log.error(err)
            traceback.print_stack()
            return 'socket_error'

    def get_hostname_by_ipv4(self,ipv4):
        try:
            hostname=socket.gethostbyaddr(ipv4)
            self.log.info(f"Hostname for {ipv4} is- {hostname[0]}")
            return hostname[0]
        except socket.error as err:
            self.log.error(err)
            traceback.print_stack()
            return 'socket_error'

    def validate_ipv4(self,ipv4):
        try:
            socket.inet_aton(ipv4)
            self.log.info(f"IPv4 {ipv4} is- valid")
            return 'valid'
        except socket.error as err:
            self.log.error(err)
            traceback.print_stack()
            return 'socket_error'

    def check_connectivity_ipv4(self,ipv4,port,timeout):
        try:
            socket.setdefaulttimeout(timeout)
            conx=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            conx_status=conx.connect_ex((ipv4,port))
            if conx_status==0:
                self.log.info(f"{ipv4} is reachable at port {port}")
                return 'reachable'
            else:
                self.log.critical(f"{ipv4} is unreachable at port {port}")
                return 'unreachable'
        except socket.error as err:
            self.log.error(err)
            traceback.print_stack()
            return 'socket_error'
        finally:
            conx.close()

    def get_port_number(self):
        try:
            conx=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            conx.bind(('',0))
            conx.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            return conx.getsockname()[1]
        except socket.error as err:
            self.log.error(err)
            traceback.print_exc(err)
            return 'socket_error'
        finally:
            conx.close()


class Authentication:

    def __init__(self):
        self.log=Log()

    def generate_token(self,length):
        try:
            token=secrets.token_hex(int(length))
            return token
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'

    def generate_token2(self,length):
        try:
            token=secrets.token_urlsafe(int(length))
            return token
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'

    def generate_uuid(self,uuid_type):
        try:
            if uuid_type=='uuid1':
                return str(uuid.uuid1())
            elif uuid_type=='uuid4':
                return str(uuid.uuid4())
            else:
                self.log.critical(f"Invalid UUID type")
                return None
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'

    def generate_random_string(self,length):
        try:
            letters=string.ascii_lowercase
            random_string=''.join(random.choice(letters) for i in range(length))
            return random_string
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'

    def hash_password(self,password):
        try:
            self.log.info(f"Hashing password with SHA256")
            secret=hash.sha256_crypt.encrypt(password)
            return secret
        except ValueError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'value_error'

    def validate_password(self,secret,password):
        try:
            self.log.info(f"Validating password with SHA256 hash")
            status=hash.sha256_crypt.verify(password,secret)
            if status is True:
                self.log.info(f"Password is valid")
                return 'valid'
            else:
                self.log.info(f"Password is invalid")
                return 'invalid'
        except ValueError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'value_error'

    def encrypt_password(self,password):
        try:
            self.log.info(f"Encrypting password")
            key=Fernet.generate_key()
            cipher_suite=Fernet(key)
            encrypted_password=cipher_suite.encrypt(bytes(password,'utf-8'))
            self.log.info(f"Password encrypted successfully")
            return encrypted_password,key
        except ValueError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'value_error'

    def decrypt_password(self,key,encrypted_password):
        try:
            self.log.info(f"Decrypting password")
            cipher_suite=Fernet(key)
            decrypted_password=cipher_suite.decrypt(encrypted_password).decode('utf-8')
            self.log.info(f"Password decrypted successfully")
            return decrypted_password
        except ValueError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'value_error'

    def http_basic_authentication(self,username,password):
        try:
            bo=f"{username}:{password}".encode()
            auth_token=b64encode(bo).decode("ascii")
            return auth_token
        except EnvironmentError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'environment_error'

    def http_digest_authentication(self,username,password):
        try:
            auth_token=HTTPDigestAuth(username,password)
            return auth_token
        except EnvironmentError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'environment_error'

    def create_http_header(self,header_type,token,address):
        try:
            if header_type=='authentication':
                self.log.info(f"Creating HTTP header for CMS authentication")
                header={'Content-Type':'application/x-www-form-urlencoded','Authorization':f'Basic {token}',
                    'Accept':"*/*",'Cache-Control':"no-cache",'Host':f"{address}",
                    'Accept-Encoding':"gzip, deflate",'Connection':"keep-alive"}
                return header
            elif header_type=='services':
                self.log.info(f"Creating HTTP header for CMS services")
                header={'Content-Type':'application/vnd.virsec.v1+json','Authorization':f'bearer {token}',
                    'Accept':"*/*",'Cache-Control':"no-cache",'Host':f"{address}",
                    'Accept-Encoding':"gzip, deflate",'Connection':"keep-alive"}
                return header
            elif header_type=='digest':
                self.log.info(f"Creating HTTP header for digest authentication")
                header=token.build_digest_header('GET',address)
                return header
            elif header_type=='basic':
                self.log.info(f"Creating HTTP header for basic authentication")
                header={'Authorization':f'basic {token}','Accept':"*/*",'Cache-Control':"no-cache",
                    'Host':f"{address}",'Accept-Encoding':"gzip, deflate",'Connection':"keep-alive"}
                return header
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'


class Connect:

    def __init__(self):
        pass

    class HTTP:

        def __init__(self,url,header,payload='',session=None,params=""):
            self.url=url
            self.header=header
            self.payload=payload
            self.session=session
            self.log=Log()
            self.params=params

        def request(self,operation,return_empty_response=False):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            try:
                if self.session is None:
                    self.log.debug(f"Creating new HTTP session")
                    with requests.Session() as session:
                        self.log.debug(f"Sending HTTP request")
                        self.log.debug(f"URL: {self.url} | Header: {self.header} | Payload: {self.payload}")
                        response=session.request(operation,url=self.url,headers=self.header,data=self.payload,
                            verify=False,params=self.params,timeout=was.configuration["timeout"])
                        self.log.debug(f"{response.status_code} | {response.text}")
                elif self.session is not None:
                    self.log.debug(f"Using HTTP session {self.session}")
                    self.log.debug(f"Sending HTTP request")
                    response=self.session.request(operation,url=self.url,headers=self.header,data=self.payload,
                        verify=False,timeout=was.configuration["timeout"])
                    self.log.debug(f"{response.status_code} | {response.text}")
            except requests.exceptions.ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except requests.exceptions.HTTPError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'http_error'
            except requests.exceptions.Timeout as t:
                self.log.error(f"Request timeout; url :{self.url}")
                return 'timeout'
            except BaseException as err:
                self.log.error(err)
                traceback.print_stack()
                return 'base_exception'

            if operation.upper()=='GET' or 'POST' or 'PUT' or 'DELETE':
                ##### CMS_TOKEN##########
                if response.status_code not in [204,401]:
                    try:
                        value=loads(response.text)
                        return value
                    except JSONDecodeError as err:
                        self.log.critical(err)
                        return 'decode_error'
                else:
                    if (return_empty_response):
                        return response
                    return None
                ###########################

        def get(self,return_empty_response=False):
            response=self.request("GET",return_empty_response)
            return response

        def add(self):
            response=self.request("POST")
            return response

        def edit(self):
            response=self.request("PUT")
            return response

        def delete(self):
            response=self.request("DELETE")
            return response

        #TODO: Murali change
        ##### CMS_TOKEN##########
        def post(self,return_empty_response=False):
            response=self.request("POST",return_empty_response)
            return response
        ######################

    class SSH:

        def __init__(self,host):
            self.host=host
            self.log=Log()

        def connect(self,username,password,transport=False,destination_host=None,destination_username=None,
                    destination_password=None):
            try:
                self.log.debug(f"Establishing SSH channel")
                client=paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.log.info(f"Connecting to host {self.host}")

                if transport==False:
                    client.connect(hostname=self.host,username=username,password=password,look_for_keys=False)
                    channel=client.invoke_shell()
                    return client,channel
                elif transport==True:
                    transport_client=paramiko.SSHClient()
                    transport_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    transport_client.connect(hostname=destination_host,username=destination_username,
                        password=destination_password,look_for_keys=False)

                    transport_client=transport_client.get_transport()
                    transport_channel=transport_client.open_channel("direct-tcpip",dest_addr=(destination_host,22),
                        src_addr=(self.host,22))
                    client.connect(hostname=destination_host,username=destination_username,
                        password=destination_password,
                        sock=transport_channel)
                    channel=client.invoke_shell()
                    return client,channel

            except ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except TimeoutError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'timeout_error'

        def transport(self,username,password,destination_address):
            try:
                client=paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=self.host,username=username,password=password,look_for_keys=False)
                transport=client.get_transport()

            except ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def execute(self,channel,command):
            try:
                self.log.info(f"Executing command {command}")
                channel.send(command+'\n')
                output=channel.recv(9999).decode('utf-8','ignore').split('\n')
                self.log.info(output)
                return output
            except paramiko.ssh_exception.ChannelException as err:
                self.log.error(err)
                traceback.print_stack()
                return 'channel_error'

        def execute_wait(self,channel,command,expect=None):
            self.log.info(f"Executing command {command}")
            incomplete=True
            try:
                channel.send(command+'\n')
                while incomplete:
                    while not channel.recv_ready():
                        time.sleep(5)
                    time.sleep(1)
                    output=channel.recv(9999).decode('utf-8','ignore').split('\n')

                    for line in output:
                        line=line.strip()
                        self.log.info(line)
                        if expect in line:
                            incomplete=False
            except paramiko.ssh_exception.ChannelException as err:
                self.log.error(err)
                traceback.print_stack()
                return 'channel_error'

        def secure_copy_files(self,client,local_directory,remote_directory,operation='pull'):
            try:
                if operation=='push':
                    with SCPClient(client.get_transport()) as scp:
                        self.log.info(f"Transferring {local_directory} to {remote_directory}")
                        scp.put(local_directory,remote_directory)
                elif operation=='pull':
                    with client.open_sftp() as scp_client:
                        self.log.info(f"Transferring {remote_directory} to {local_directory}")
                        scp_client.get(remote_directory,local_directory)
            except paramiko.ssh_exception.ChannelException as err:
                self.log.error(err)
                traceback.print_stack()
                return 'channel_error'

        def secure_copy_directories(self,channel,directories,remote_location):
            try:
                with SCPClient(channel.get_transport()) as scp:
                    scp.put(directories,remote_location)
            except paramiko.ssh_exception.ChannelException as err:
                self.log.error(err)
                traceback.print_stack()
                return 'channel_error'

    class Windows:

        def __init__(self,host):
            self.host=host
            self.log=Log()

        def ntlm(self,username,password,domain=None,session=None):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            try:
                self.log.debug(f"Creating new NTLM session")
                with requests.Session() as session:
                    if domain:
                        session.auth=HttpNtlmAuth(f"{domain}//{username}",password)
                        self.log.debug(f"Adding session authentication with domain {domain} & username {username}")
                    else:
                        self.log.debug(f"Adding session authentication without domain with username {username}")
                        session.auth=HttpNtlmAuth(username,password)

                    #response = session.get(f"https://{self.host}", verify=False)
                    response=session.get(str(self.host),verify=False)  #changed
                    self.log.debug(f"{response}")
                    if response.status_code==200:
                        self.log.info(f"NTLM authentication validation successful")
                        return 'success'
                    else:
                        self.log.info(f"NTLM authentication validation not successful")
                        return 'failure'
            except requests.exceptions.ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def connect(self,username,password,port=445,encrypt=False):
            try:
                self.log.info(f"Establishing remote windows channel")
                win=Client(server=self.host,username=username,password=password,port=port,encrypt=encrypt)
                self.log.info(f"Connecting to host {self.host}")
                channel=win.connect(timeout=180)
                return channel
            except ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def connect2(self):
            pass

        def execute(self,channel,command,arguments,run_elevated=True,use_system_account=False,asynchronous=False):
            try:
                service=channel.create_service()
                stdout,stderr,pid=service.run_executable(executable=command,arguments=arguments,
                    run_elevated=run_elevated,
                    use_system_account=use_system_account,
                    asynchronous=asynchronous)
                if stderr:
                    self.log.critical(stderr)
                return service,stdout,pid
            except ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def disconnect(self,service):
            try:
                service.remove_service()
                service.disconnect()
            except ConnectionError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'


class Database:

    def __init__(self):
        pass

    class Redis:

        def __init__(self):
            self.log=Log()

        def connect(self,host='localhost',port=6379):
            try:
                self.log.debug(f"Establishing connection with cache")
                redis=Redis(host=host,port=port)
                return redis
            except RedisError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'redis_error'

        def get_key_from_value(self,channel,value):
            try:
                keys=channel.keys()
                self.log.debug(f"Keys: {keys}")
                for key in keys:
                    val=channel.mget(key.decode('utf-8'))
                    if val[0]==bytes(value,'utf-8'):
                        self.log.info(f"Key for {value} found")
                        return key.decode('utf-8')
                    else:
                        continue
                self.log.warning(f"Key for {value} not found")
                return 'key_not_found'
            except RedisError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'redis_error'

        #Murali Change: Stale state
        ###########################
        def set_status_value(self,redis_obj,key,app_id,**state_values):
            cache_map={'application_id':app_id}
            cache_map.update(state_values)
            redis_obj.hmset(key,{app_id:str(cache_map)})
        ###########################

    class Mongo:

        def __init__(self):
            self.log=Log()

        def connect(self,host='localhost',port=27017):
            try:
                self.log.debug(f"Establishing connection with database")
                mongo=MongoClient(host=host,port=port,connect=True)

                return mongo
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def create_database(self,channel,database):
            try:
                self.log.debug(f"Creating new or using existing database: {database}")
                db=channel[database]
                return db
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def create_collection(self,database,collection):
            try:
                self.log.debug(f"Creating new or using existing collection: {collection}")
                coll=database[collection]
                return coll
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def insert_document(self,collection,document):
            try:
                self.log.debug(f"Inserting document {document}")
                doc=collection.insert_one(document)
                if doc.acknowledged is True:
                    self.log.debug(f"Document {document} added successfully")
                    return 'insert_success'
                else:
                    self.log.critical(f"Document {document} could not add successfully")
                    return 'insert_failure'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except errors.WriteError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_error'
            except errors.WriteConcernError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_concern_error'

        def insert_documents(self,collection,documents):
            try:
                self.log.debug(f"Inserting documents {documents}")
                doc=collection.insert_many(documents)
                if doc.acknowledged is True:
                    self.log.debug(f"Documents {documents} added successfully")
                    return 'insert_success'
                else:
                    self.log.warning(f"Documents {documents} could not add successfully")
                    return 'insert_failure'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except errors.WriteError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_error'
            except errors.WriteConcernError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_concern_error'
            except errors.BulkWriteError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'bulk_write_error'

        def find_databases(self,channel):
            try:
                self.log.debug(f"Fetching list of databases")
                dbs=channel.list_database_names()
                self.log.debug(f"Databases: {dbs}")
                return dbs
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def find_collections(self,database):
            try:
                self.log.debug(f"Fetching list of collections")
                colls=database.list_collection_names()
                self.log.debug(f"Collections: {colls}")
                return colls
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def find_document(self,collection,pattern='{}',field=''):
            try:
                self.log.debug(f"Finding documents with pattern {pattern} for field {field} in {collection}")
                if field:
                    doc=collection.find_one(pattern,field)
                else:
                    doc=collection.find_one(pattern)
                self.log.debug(f"Document: {doc}")
                if doc:
                    self.log.debug(f"Document found")
                    return doc
                else:
                    self.log.warning(f"Document not found")
                    return 'document_not_found'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def find_documents(self,collection,pattern='{}'):
            try:
                self.log.debug(f"Finding documents with field {pattern} in {collection}")
                docs=[doc for doc in collection.find(pattern)]
                self.log.debug(f"Documents: {docs}")
                if docs:
                    self.log.debug(f"Documents found")
                    return docs
                else:
                    self.log.warning(f"Documents not found")
                    return 'documents_not_found'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def find_all_documents(self,collection):
            try:
                self.log.debug(f"Finding documents from {collection}")
                docs=[doc for doc in collection.find()]
                # self.log.debug(docs)
                if docs:
                    self.log.debug(f"Documents found")
                    return docs
                else:
                    self.log.warning(f"Documents not found")
                    return 'documents_not_found'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def update_document(self,collection,field,pattern='{}',upsert=False):
            try:
                self.log.debug(f"Updating {field} for document in collection {collection}")
                doc=collection.update_one(pattern,field,upsert=upsert)
                if doc.acknowledged is True:
                    self.log.debug(f"Document updated successfully")
                    return 'update_success'
                else:
                    self.log.warning(f"Document could not update successfully")
                    return 'update_failure'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except errors.WriteError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_error'
            except errors.InvalidDocument as err:
                self.log.error(err)
                traceback.print_stack()
                return 'invalid_document'

        def update_documents(self,collection,field,pattern='{}'):
            try:
                self.log.debug(f"Updating {field} for document in collection {collection}")
                doc=collection.update_many(pattern,field,upsert=True)
                if doc.acknowledged is True:
                    self.log.debug(f"Document updated successfully")
                    return 'update_success'
                else:
                    self.log.warning(f"Document could not update successfully")
                    return 'update_failure'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'
            except errors.WriteError as err:
                self.log.error(err)
                traceback.print_stack()
                return 'write_error'
            except errors.InvalidDocument as err:
                self.log.error(err)
                traceback.print_stack()
                return 'invalid_document'

        def delete_document(self,collection,pattern='{}'):
            try:
                self.log.debug(f"Deleting document from collection {collection}")
                status=collection.delete_one(pattern)
                if status.acknowledged is True:
                    return 'delete_success'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def delete_documents(self,collection,pattern='{}'):
            try:
                self.log.debug(f"Deleting document from collection {collection}")
                status=collection.delete_many(pattern)
                if status.acknowledged is True:
                    return 'delete_success'
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def drop_database(self,channel,database):
            try:
                self.log.debug(f"Dropping database {database}")
                status=channel.drop_database(database)
                self.log.debug(status)
                return status
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def drop_collection(self,channel,collection):
            try:
                self.log.debug(f"Dropping collection {collection}")
                status=channel.drop_collection()
                self.log.debug(status)
                return status
            except errors.ConnectionFailure as err:
                self.log.error(err)
                traceback.print_stack()
                return 'connection_error'

        def update_collection():
            coll=self.mongo.create_collection(db_obj,collection_name)
            self.mongo.update_document(coll,{'$set':{'detail.state':'attacking'}},
                {'application_id':application_id},upsert=True)
            self.mongo.update_document(coll,{'$set':{'attack.attack_state':'instantiated',
                'attack.attack_instantiated':start_time}},
                {'application_id':application_id},upsert=True)
        # def update_table_with_cache(db_obj, collection_name,redis_obj,app_id):
        #     cache_map = {'application_id': app_id, 'attack_state': 'instantiated'}
        #     redis_obj.hmset('attack', {app_id: str(cache_map)})
        #     redis_obj.hset(app_id, 'attack_state', 'instantiated')
        #     set_status_value


class ConvertData:

    def __init__(self,data):
        self.data=data
        self.log=Log()

    def payload_to_json(self):
        try:
            self.log.info(f"Converting user input to system compatible format")
            output=loads(request.get_data(self.data).decode("utf-8"))
            self.log.debug(output)
            return output
        except decoder.JSONDecodeError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'decode_error'

    def dict_to_json(self):
        try:
            self.log.info(f"Converting dictionary to JSON format")
            output=loads(dumps(self.data))
            self.log.debug(output)
            return output
        except decoder.JSONDecodeError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'decode_error'

    def json_to_string(self):
        try:
            self.log.info(f"Converting JSON to string format")
            output=dumps(self.data)
            self.log.debug(output)
            return output
        except decoder.JSONDecodeError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'decode_error'

    def framework_compatible(self):
        try:
            self.log.debug(f"Converting data to system compatible format")
            # data = self.data.replace("'", "\"")
            # if 'False' in data:
            #     data = data.replace('False', 'false')
            # if 'True' in data:
            #     data = data.replace('True', 'true')
            # if 'None' in data:
            #     data = data.replace('None', 'null')
            # output = loads(data)
            data=self.data
            if 'False' in data:
                data=data.replace('False','false')
            if 'True' in data:
                data=data.replace('True','true')
            if 'None' in data:
                data=data.replace('None','null')
            #data=eval(self.data)
            self.log.debug(data)
            return eval(data)
        except decoder.JSONDecodeError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'decode_error'

    def summary(self):
        try:
            self.log.debug(self.data)
            return self.data
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'exception'

    def byte_to_string(self):
        try:
            data=self.data.decode('utf-8')
            return data
        except Exception as err:
            self.log.error(err)
            traceback.print_stack()
            return 'decode_error'

    def xml_root(self):
        try:
            tree=ET.parse(self.data)
            root=tree.getroot()
            return root
        except ET.ParseError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'xml_parse_error'

    def xml_to_json(self):
        try:
            self.log.info(f"Converting XML to JSON")
            data=xmltodict.parse(self.data)
            return data
        except xmltodict.expat.ExpatError as err:
            self.log.error(err)
            traceback.print_stack()
            return 'xml_parse_error'

    def file_size(self):
        position=self.data.tell()
        self.data.seek(0,os.SEEK_END)
        file_size=self.data.tell()
        self.data.seek(position)
        return file_size


class Report:

    def __init__(self):
        pass


# TODO: SMTP: Murali changes
###########################
class Email:
    HOST=""
    PORT=""
    PROTOCOL=""
    SENDER=""
    RECEIVER=[]
    PASSWORD=""
    EMAIL_TEMPLATE="""
            <p>{content}</p>
            """

    def __init__(self):
        self.log=Log()

    def login_into_smtp(self,smtpObj):
        try:
            smtpObj.login(Email.SENDER,Email.PASSWORD)
            return True
        except Exception as e:
            self.log.error(f"Exception raised when creating SMTP object: {e}")
            return None

    def get_smtp_obj(self):
        try:
            smtpObj=None
            if Email.PROTOCOL=="ssl":
                smtpObj=smtplib.SMTP_SSL(Email.HOST,Email.PORT)  # smtplib.SMTP_SSL
            elif Email.PROTOCOL.lower() in ["tls","none"]:
                smtpObj=smtplib.SMTP(Email.HOST,Email.PORT)
                if Email.PROTOCOL.lower()=="tls":
                    smtpObj.connect(Email.HOST,Email.PORT)
                    smtpObj.starttls()
                    smtpObj.ehlo()
            else:
                self.log.error("SMTP not configured in configuration page")
                # raise ValueError(f"Protocol found as:{Email.PROTOCOL}")
                # smtpObj = self.validate(  smtp_host=was.was['email']["server"],
                #                 smtp_port=was.was['email']["port"],
                #                 protocol=was.was['email']["protocol"],
                #                 sender=was.was['email']["sender_address"],
                #                 password=was.was['email']["sender_password"],
                #                 receiver=[]
                #             )
            return smtpObj
        except smtplib.SMTPException as e:
            self.log.error(f"SMTP Exception raised: {e}")
            return None
        except Exception as e:
            self.log.error(f"Exception raised when creating SMTP object: {e}")
            return None

    def validate(self,smtp_host,smtp_port,protocol,sender,password,receiver):
        Email.HOST=smtp_host or was.was['email']["server"]
        Email.PASSWORD=password or was.was['email']["sender_password"]
        Email.SENDER=sender or was.was['email']["sender_address"]
        # Email.PASSWORD = was.was['email']["sender_password"]
        # Email.HOST = was.was['email']["server"]
        # Email.PORT = was.was['email']["port"]
        Email.PROTOCOL=protocol or was.was['email']["protocol"]
        Email.PORT=smtp_port or was.was['email']["port"][Email.PROTOCOL.upper()]
        #Email.SENDER = was.was['email']["sender_address"]
        Email.RECEIVER=receiver or []
        try:
            smtpObj=self.get_smtp_obj()
            if smtpObj!=None:
                if self.login_into_smtp(smtpObj)!=None:
                    smtpObj.quit()
                    return 235

        except (smtplib.SMTPAuthenticationError,smtplib.SMTPConnectError,
        smtplib.SMTPNotSupportedError,ConnectionResetError) as e:
            self.log.error(f"SMTP Exception raised: {e}")
            return e
        except Exception as e:
            self.log.error(f"Exception raised: {e}")
            return e


class Notification(Email):
    def flash(self,timestamp,level,operation,message,application_id,application_name):
        self.redis=Database().Redis()
        cache_channel=self.redis.connect(host=was.was['cache'])
        display={}
        notify_id='notify_'+str(random.randint(0,9))
        #display[notify_id]={}
        display['notification_id']=notify_id
        display['level']=level
        display['application_id']=application_id
        display['application_name']=application_name
        display['message']=message
        display['operation']=operation
        display['timestamp']=timestamp
        display['state']='unread'
        notifications="notifications"

        cache_channel.hset(notifications,notify_id,str(display))

    def smtp(self,subject,message):
        smtpobj=self.get_smtp_obj()
        if (smtpobj==None):
            self.log.error("SMTP not configured in configuration page; thus email not triggered")
            return
        if (self.login_into_smtp(smtpobj)!=None):
            for receiver in Email.RECEIVER:
                mail_body=""
                msg=MIMEMultipart('alternative')
                mail_body=Email.EMAIL_TEMPLATE.format(
                    content=message
                )
                msg['From']=formataddr((str(Header('WAS Service Mail','utf-8')),Email.SENDER))
                msg['To']=receiver
                msg['subject']=subject
                msg.attach(MIMEText(mail_body,'html'))
                smtpobj.sendmail(Email.SENDER,receiver,msg.as_string())
        smtpobj.quit()

    def send_notification(self,message,operation,application_id="",application_name="",subject=""):
        self.flash(timestamp=time.time(),level='INFO',operation=operation,
            message=message,application_id=application_id,
            application_name=application_name)
        if (subject):
            self.smtp(subject=subject,message=message)
###########################

