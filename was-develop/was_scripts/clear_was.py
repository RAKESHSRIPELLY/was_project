import redis
from pymongo import MongoClient
import time
class ClearAll :
    def __init__(self,host='localhost', port = 6379):
        try:
            self.r = redis.Redis(host=host, port=port)
            self.client = MongoClient()
            self.mydatabase = self.client['was_db']
        except RedisError as err:
            print(err)
            
    def clearDb(self):
        try:
            self.application = self.mydatabase['applications']
            self.url_store = self.mydatabase['url_store']
            self.dashboard = self.mydatabase['dashboard']
            self.configuration = self.mydatabase['configuration']
            self.pre_crawl = self.mydatabase['pre_crawl_store']
            self.temp_url = self.mydatabase['temp_url_store']
            reports =self.mydatabase['reports']
            delete_list=[self.application,self.url_store,self.dashboard, self.configuration,self.pre_crawl,self.temp_url,reports]
            for i in delete_list:
                x = i.delete_many({})
        except Exception as err:
            print(err)
            
    def clearRedis(self):
        try:
            status = self.r.flushall()
            status = self.r.flushdb()
            
        except Exception as err:
            print(err)
            
if __name__=="__main__":
    start = ClearAll()
    start.clearDb()
    time.sleep(5)
    start.clearDb()
    print("WAS Db Cleared Succesfully")
    start.clearRedis()
    time.sleep(5)
    start.clearRedis()
    print("Cache Cleared Succesfully")
