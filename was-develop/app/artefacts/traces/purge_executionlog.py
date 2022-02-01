import datetime,csv
today=datetime.datetime.today()
removelog=[]
todaylogs=[]
def remove_unwanted_logs():
        
    with open("execution.log",'r') as logfile:
        reader=logfile.readlines()
        yield (i for i in reader)
fun=remove_unwanted_logs()

for log in fun:
    for i in log:
        try:                
            sep = i.split('|')[0].split(',')[0]
            format = '%Y-%m-%d %H:%M:%S'
            day = datetime.datetime.strptime(sep,format)
        except:
            pass        
        if today<=day:
            todaylogs.append(i)
        else:
            removelog.append(i)
del removelog
print(todaylogs)
print(len(todaylogs))