import os
import subprocess
from random import randint
def stop_was():
    ui_version = "" 
    cmd = "sudo systemctl stop was.service"
    os.system(cmd)
    print("was services has stopped")
    version_check = 'sudo docker ps --format "{{.Names}}"'
    
    ui_version = subprocess.check_output(version_check, shell=True)
    
    if (len(ui_version) != 0):
        cmd = "sudo docker stop " + str(ui_version.decode("utf-8"))
        os.system(cmd)
        print("WAS UI has stopped")
        remove_docker = "sudo docker rm --force "+ str(ui_version.decode("utf-8"))
        os.system(remove_docker)
        print("Wasui Removed")
    else:
        print("No any WASUI is running")
	
    	
def was_installation():
    
    if os.path.exists('was'):
        remove_was = "sudo rm -r was"
        os.system(remove_was)
        
        print("Updating WAS...")
        new_tar = "tar -xvf" + 'was_v_2_0_11_HF25102021.tar.gz' + " >> was_installation_log.txt"
        os.system(new_tar)
        load_docker = "sudo docker load -i wasui-1.2.0.25.tar.gz"
        os.system(load_docker)
        name = 'wasui'+str(randint(100, 999))
        run_docker = "sudo docker run -d --restart unless-stopped -p 80:80 -p 443:443 --name {0} wasui:latest".format(name)
        os.system(run_docker)
        print("New Version Of WAS Successfully Installed")
        
        startwas= "sudo systemctl start was.service"
        os.system(startwas)
        print("was service started")
        try:
            del_log = "rm was_installation_log.txt" 
            os.system(del_log)
        except e:
            raise e
    else:
        print("WAS Floder is not present")
        


stop_was()
was_installation()



 

