__author__='JG'

import os,signal
from lib import utility as util  #, framework as fw
from config import was,environment as env
import requests
from crawl.CrawlProcess import Crawler,CrawlerUtils,Manual
import subprocess


class Crawl:

    def __init__(self,application_id):
        self.application_id=application_id

        self.log=util.Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()

    def initiate(self,user_input):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            app_coll=self.mongo.create_collection(db,'applications')
            app_doc=self.mongo.find_document(app_coll,{'application_id':self.application_id})
            us_coll=self.mongo.create_collection(db,'url_store')
            us_doc=self.mongo.find_document(us_coll,{'application_id':self.application_id})
            Crawler(applicationId=self.application_id,applicationName=app_doc['detail']['name'],
                applicationURL=us_doc['authentication']['homepage_url'],
                crawlType=user_input['crawl']['type'],usersInfo=user_input['crawl']['users']).crawlProcess()




        finally:
            if cache_channel:
                del cache_channel
            if db_channel:
                db_channel.close()

    def pause(self):
        try:
            CrawlerUtils(self.application_id).pauseCrawl()
        except Exception as err:
            self.log.error(err)

    def resume(self):
        try:
            CrawlerUtils(self.application_id).resumeCrawl()
        except Exception as err:
            self.log.error(err)

    def terminate(self):
        try:
            Crawler(self.application_id).stopCrawl()
        except Exception as err:
            self.log.error(err)

    def progress(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')

            app_coll=self.mongo.create_collection(db,'applications')
            app_doc=self.mongo.find_document(app_coll,{'application_id':self.application_id})
            us_coll=self.mongo.create_collection(db,'url_store')
            us_doc=self.mongo.find_document(us_coll,{'application_id':self.application_id})
            percent=CrawlerUtils(applicationId=self.application_id).crawlPercentage()
            return percent
        except Exception as err:
            self.log.error(err)

    def application_pre_crawl(self,):
        try:
            if self.stop_mitm():
                Manual(self.application_id).precrawl()

        except Exception as err:
            self.log.error(err)

    def start_mitm(self):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            mitm_config=was.configuration['manual_crawl']
            #mitm_cmd="./mitmdump -s uploadLog.py"
            mitm_cmd=f"./{mitm_config['mitm_executor']} -s {mitm_config['mitm_process_py']}"
            process=subprocess.Popen(mitm_cmd.split(),shell=False,cwd=mitm_config['mitm_location'])
            if process.poll()==None:
                self.log.info(f"MITMDump started for {self.application_id} with id: {process.pid}")
                coll=self.mongo.create_collection(db,'pre_crawl_store')
                status=self.mongo.update_document(coll,{'$set':{'manual.processid':process.pid}}
                    ,{'application_id':self.application_id},upsert=True)
                return True
            self.log.critical(f"MITMDump was not started for {self.application_id}")
            return False
        finally:
            if db_channel:
                db_channel.close()

    def stop_mitm(self):
        try:
            db_channel=self.mongo.connect(host=was.was['database'])
            #'was_db'=was.environment["current_db"]
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'pre_crawl_store')
            pre_crawl=self.mongo.find_document(coll,{'application_id':self.application_id})
            pid=pre_crawl['manual']['processid'] if 'processid' in pre_crawl['manual'].keys() else None
            if pid!=None:
                try:
                    os.kill(pid,signal.SIGINT)
                    return True
                except ProcessLookupError as pe:
                    self.log.critical(f"MITMDump process was already killed {self.application_id}")
                    return False

        finally:
            if db_channel:
                db_channel.close()







