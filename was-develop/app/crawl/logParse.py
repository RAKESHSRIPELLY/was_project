import json
import sys


def formatLog(fileLocation,fileName):
	try:
		filePath = fileLocation+'/'+fileName
		logFile = open(filePath, 'r')
		log = logFile.read()
		logFile.close()

		lines = log.splitlines()

		data = {}

		entry = {}
		parsingHeader = False

		for line in lines:
			if line == '': continue

			if line.startswith('--'):
				[id, part] = [x for x in line.split('-') if x != '']
				if(id not in data): data[id] = []
				entry = {'part': part}
				data[id].append(entry)
				parsingHeader = True
				continue

			if parsingHeader:
				entry['header'] = line
				if entry['part'] == 'B':
					headerFields = line.split(' ')
					entry['method'] = headerFields[0]
					entry['path'] = headerFields[1]
				parsingHeader = False
				continue
			(k, _, v) = line.partition(':')
			entry[k] = v

		try:
			jsonPath = fileLocation+'/'+'logOutput.json'
			print(jsonPath)
			with open(jsonPath, 'w') as outfile:
				json.dump(data, outfile)
		except Exception as e:
			print('Unable to Process LogParse : Generate Log JSON.')
			print('Exception',e)
			sys.exit(2023)

	except Exception as e:
		print('Unable to Process LogParse : Format JSON.')
		print('Exception',e)
		sys.exit(2024)