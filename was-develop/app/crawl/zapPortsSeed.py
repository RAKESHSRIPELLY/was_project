from pymongo import MongoClient
from datetime import datetime
#from config.was import environment
import sys
#from config.was.was import was

mongoClient = MongoClient(host='10.42.3.252')
#was_db=was.environment["current_db"]
dbConn = mongoClient['was_db_10_20_12_32']
mongoTable = dbConn['zap_ports']
mongoTable.drop()


zapIP = '0.0.0.0'

seedData = [
  {"zapIP" : zapIP, "zapPort" : 2030, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2031, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2032, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2033, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2034, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2035, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2036, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2037, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2038, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() },
  {"zapIP" : zapIP, "zapPort" : 2039, "portStatus" : "active", "applicationName" : 'none', "applicationId" : 'none', "applicationAPIKey" : 'none', "applicationURL" : 'none', "scanId": 'none', "processId": 'none', "created_dt" : datetime.now().isoformat(), "updated_dt" : datetime.now().isoformat() }
]

try:
  seedDataInsert = mongoTable.insert_many(seedData)

  if seedDataInsert:
    print('Seed Data Inserted...')

except Exception as e:
  print('Exception', e)
  print('Unable to Insert Seed Data.')
  sys.exit(2024)
