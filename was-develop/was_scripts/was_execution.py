import os


	
def was_exec(counter):
	check = input("WAS(Start/Stop) : ")
	
	if check.upper() == "START":
					cmd = "sudo systemctl start was.service"
					os.system(cmd)
					print("was service started")
					cmd = "sudo docker start wasui23"
					os.system(cmd)
					print("WAS UI has started")

	elif check.upper() == "STOP":
					cmd = "sudo systemctl stop was.service"
					os.system(cmd)
					print("was services has stopped")
					cmd = "sudo docker stop wasui23"
					os.system(cmd)
					print("WAS UI has stopped")

	else:
					counter +=1
					print("Invalid Option")
					if counter < 3 :
						was_exec(counter)
					else:
						print("Number of Attempts Exceeded")
						



def main():
	counter = 0
	was_exec(counter)

main()
