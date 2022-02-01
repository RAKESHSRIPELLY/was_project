import time
import os
import sys
import logParse
from config import was
import json
from datetime import datetime
from pymongo import MongoClient

# Notes:
# 1. logFileDir  - Path should not end with /

class UploaderJob:
	def __init__(self,crawlType):

		self.logFileDir = '/var/log'
		self.logFile = 'modsec_audit.log'
		self.crawlType = crawlType
		self.JSONExtract = ''

		self.processIds = []
		self.processIdsTemp = []
		self.jsonFinal = []

		self.mongoClient = MongoClient()
		#was_db=was.environment["current_db"]
		self.dbConn = self.mongoClient['was_db']
		self.mongoTable = self.dbConn['temp_url_store']  


	def logToJSON(self):
		try:
			logParse.formatLog(self.logFileDir, self.logFile)
		except Exception as e:
			print('Unable to Process UploaderJob : logToJSON.')
			print('Exception', e)
			sys.exit(2025)

	def fileMonitoring(self, timeInterval):
		try:
			self.logToJSON()
			with open(self.logFileDir+'/logOutput.json') as fileContent:
				self.JSONExtract = json.load(fileContent)

			jsonFileKeys = set(self.JSONExtract.keys())

			if len(jsonFileKeys) <= 0:
				self.processIdsTemp = []

			if len(jsonFileKeys) >= 1:
				self.processIds = list(jsonFileKeys - set(self.processIdsTemp))
				self.processIdsTemp = self.processIdsTemp + self.processIds

				self.jsonFinal = []
				if self.processIds:
					print('Processing Data...')
					for process in self.processIds:
						for processData in self.JSONExtract[process]:
							if processData['part'] == 'B':
								partBMethod = (processData['method']).strip()
								partBhost = (processData['Host']).strip()
								partBPath = (processData['path']).strip()
								partBUserAgent = (processData['User-Agent']).strip()

								tempDict = { "hostname" : partBhost ,"attack_url" : partBPath ,"request_type" : partBMethod , "user_agent" : partBUserAgent , "exercisable_parameters" : [], "parameters" : {} }
								self.jsonFinal.append(tempDict)

				if len(self.jsonFinal) >= 1:
					self.mongoTable.insert_many(self.jsonFinal)

			time.sleep(timeInterval)
		except Exception as e:
			print('Unable to Process UploaderJob : File Monitoring.')
			print('Exception', e)
			sys.exit(2022)


def main():
    try:
        uploaderInit = UploaderJob('manual')

        while True:
            uploaderInit.fileMonitoring(1)

    except Exception as e:
        print('Unable to Process UploaderJob : Main Process.')
        print('Exception: ', e)
        sys.exit(2021)

if __name__ == "__main__":
    main()
