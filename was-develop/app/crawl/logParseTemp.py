import time
import os
import sys
import json
from datetime import datetime
from config import was
from pymongo import MongoClient
from pprint import pprint


# Notes:
# 1. logFileDir  - Path should not end with /
class UploaderJob:
    def __init__(self,crawlType):
        self.logFileDir='/home/virsec'
        self.logFile='tempURLData321.json'
        self.crawlType=crawlType
        self.JSONExtract=''
        self.mongoClient=MongoClient()
        #was_db=was.environment["current_db"]
        self.dbConn=self.mongoClient['was_db']
        self.mongoTable=self.dbConn['temp_url_store']

    def createFinalJson(self):
        try:
            import json
            f=open("/home/virsec/tempURLData321.json","r")
            data=f.read()
            #print('Here')
            with open("finalURLData.json","w") as lgfile:
                lgfile.write("[")
                datanew=data[1:]
                lgfile.write(datanew)
                lgfile.write("]")

        except Exception as e:
            print('Unable to Process UploaderJob : logToJSON.')
            print('Exception',e)
            sys.exit(2025)

    def fileMonitoring(self,timeInterval):
        try:
            self.createFinalJson()
            #print('Next')
            self.jsonList=[]
            self.jsonFinal=['hostname','attack_url','user_agent','request_type','time_stamp','exercisable_parameters',
                'parameters']
            self.finalList=[]
            with open("finalURLData.json","r") as finallog:
                json_data=json.load(finallog)
                for i in json_data:
                    cursor=self.mongoTable.find({"time_stamp":i['time_stamp']})
                    #count = self.dbConn.mongoTable.count_documents({"time_stamp": i['time_stamp']})
                    count=cursor.count()
                    #add unique value inside list
                    print(count)
                    if count==0:
                        self.jsonList.append(i)
                self.del_key=set()
                #print(self.jsonList)

                for i in self.jsonList:
                    try:
                        #print("*"*10)
                        i['hostname']=i.pop('Host')
                        i['attack_url']=i.pop('requestURI')
                        i['user_Agent']=i.pop('User-Agent')
                        i['request_type']=i.pop('requestType')
                        #print(i)

                        for k,v in i.items():
                            if k.lower() not in self.jsonFinal:
                                # print("check if not prent")
                                self.del_key.add(k.lower())
                                #print("yes or no")
                    except KeyError:
                        continue

                #print(self.jsonList)
                for i in self.jsonList:
                    try:
                        if i['hostname']=='':
                            print("no hostname")
                            continue
                        else:
                            res=dict([(key,val) for key,val in i.items() if key.lower() not in self.del_key])
                            check=dict([(k.replace('.','_'),v) for k,v in res['parameters'].items()])
                            res['parameters']=check
                            #print(res)
                            self.finalList.append(res)

                    except KeyError:
                        continue
                #print(self.finalList)
                if len(self.finalList)>=1:
                    self.mongoTable.insert_many(self.finalList)
        except Exception as e:
            print('Unable to Process UploaderJob : File Monitoring.')
            print("Exception",e)
            sys.exit(2022)


def main():
    try:
        uploaderInit=UploaderJob('manual')
        #while True:
        uploaderInit.fileMonitoring(10)
    except Exception as e:
        print('Unable to Process UploaderJob : Main Process.')
        print('Exception: ',e)
        sys.exit(2021)


if __name__=="__main__":
    main()
