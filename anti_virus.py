import os
import requests
def rec_files(path, is_virus):
    directory=path
    for filename in os.listdir(directory):
        if not os.path.isdir(os.path.join(directory, filename)):
            path=os.path.join(directory, filename)
            scan_result = scan_file(path)

        else:
            is_virus=rec_files(os.path.join(directory, filename),is_virus)
    return is_virus

def scan_file(file_path):
    api_key = "c4db8c93c0a625cce07513f42c55d5aede9435e42418922cce511e9d7b48b650"
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        params = {'apikey': api_key}
        response = requests.post(url, files=files, params=params)
    
    result = response.json()
    positives = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    return 0<positives



path ='C:/Users/USER/Desktop/HomeWork4#/try'
print(rec_files(path,False))
