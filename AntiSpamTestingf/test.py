import requests
import time
spoof = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'}

while(True):
    x = requests.get('https://www.pozm.media/IsGay?user=FUCK%20GAY%20NIGGERS%20is%20fat&reason=he%20is%20fat',headers=spoof)
  
    if x.status_code == 429:
        print('WAIT 10 secs')
        time.sleep(10)
    else:
        print(x.status_code)