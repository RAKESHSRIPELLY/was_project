from mitmproxy import http
import json
from urllib.parse import urlparse,parse_qs
from datetime import datetime

exclusion_ext=['apng','avif','gif','jpg','jpeg','jfif','pjpeg','pjp','png','svg','webp','bmp','ico',
    'cur','tif','tiff','cgi','pl','shtml','txt','pdf','xml','css']


class mk_dictionary(dict):
    def __init__(self):
        self=dict()

    # Function to add key:value
    def add(self,key,value):
        self[key]=value


def response(flow):
    diob=mk_dictionary()
    d=dict(flow.request.headers.items())
    d['header']=dict(flow.request.headers)
    d['requestType']=flow.request.method
    d['time_stamp']=(datetime.now()).strftime("%Y%m%d%H%M%S%f")
    try:
        if str(flow.request.url).split(".")[-1:][0] not in exclusion_ext:
            if flow.request.method.lower()=="get":
                if ((str(flow.request.path)).count('?')>0):
                    d['requestURI']=str(flow.request.url).split('?')[0]
                    param=(str(flow.request.path).split('?')[1])
                    exparam=[]
                    i=0
                    for i in range(param.count('=')):
                        key=(param.split('&')[i]).replace('=',' : ').split(':')[0]
                        val=(param.split('&')[i]).replace('=',' : ').split(':')[1]
                        exparam.append(key)
                        diob.add(key,val)
                    d["exercisable_parameters"]=exparam
                    d["parameters"]=diob
                else:
                    d['requestURI']=str(flow.request.url)
                    d["exercisable_parameters"]=[]
                    d["parameters"]={}
            if flow.request.method.lower()=="post":
                param={}
                d['requestURI']=str(flow.request.url)
                if isinstance(flow.request.content,bytes):
                    content=flow.request.content.decode("UTF-8")
                else:
                    content=str(flow.request.content)
                for i in content.split("&"):
                    param[i.split("=")[0]]=i.split("=")[1]

                d["exercisable_parameters"]=list(param.keys())
                d["parameters"]=param

        with open("mitm_temp.json","a") as logfile:
            d=json.dumps(d,indent=4)
            logfile.write(",")
            logfile.write(d)

    except Exception as e:
        with open("mitm_temp_error.log","w") as except_file:
            except_file.write(str(e))


def main():
    response(flow)


if __name__=="__main__":
    main()
