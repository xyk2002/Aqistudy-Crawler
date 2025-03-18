# @File    :   AsyncAirQuality.py
# @Time    :   2025/03/16 16:44:07
# @Author  :   Mr.KUN
# @Version :   1.0
# @Contact :   3031657892@qq.com
# @License :   MIT LICENSE



import asyncio
import base64
import csv
import hashlib
import json
import time
from typing import Any

import aiohttp
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm

# pip install pycryptodome
# pip install aiohttp
# pip install tqdm

# 2013-1 -- 2025-3, month 135, ciyts 12, data count = 135 * 12 = 1620


TARGETCITY = ['北京', '上海', '广州', '深圳', '杭州', '天津', '南昌', '成都', '南京', '西安', '武汉', '重庆']



class CipherKeysMapper:

    AES = {
        'Encrypt': {
            'key': "84f8e58a7b19f481",
            'iv': "f41de95c205ae7a6"
        },
        'Decrypt': {
            'key': "a5dbbe8708dd6c38",
            'iv': "86b01ec583dcaaaa"
        }
    }

    DES = {
        'Encrypt': {
            'key': "d41d8cd9",
            'iv': "ecf8427e"
        },
        'Decrypt': {
            'key': "f396fe4d",
            'iv': "0b4e0780"
        }
    }


class DESCipher:

    def __init__(self, key: str, iv: str):
        self.key = key.encode()
        self.iv = iv.encode()

    def encrypt(self, text: str):
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        padded_text = pad(text.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, text: str):
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        ciphertext = base64.b64decode(text)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return decrypted_data.decode()


class AESCipher:

    def __init__(self, key: str, iv: str):
        self.key = key.encode()
        self.iv = iv.encode()

    def encrypt(self, text: str):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        padded_text = pad(text.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, text: str):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        ciphertext = base64.b64decode(text)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode("utf-8")


class AsyncAirQuality:

    def __init__(self, ciytList: list[str]):
        self.ciytList = ciytList
        self.maxConcurrentRequests = 20
        self.loop = asyncio.get_event_loop()
        self.allowRequestEvent = asyncio.Event()
        self.dbLock = asyncio.Lock()
        self.semRequest = asyncio.Semaphore(self.maxConcurrentRequests)

        self.header = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': 'https://www.aqistudy.cn/historydata/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
            'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        self.progress = tqdm(desc="-> CNVD Collect Progress", total=len(self.ciytList), colour='yellow')

    
    def storeData(self,  cityName: str, dataList: list[dict[str, Any]]):
        with open(f'{cityName}.csv', 'w+', encoding='utf-8', newline='') as f:
            csvWriter = csv.writer(f)
            csvWriter.writerow(['month', 'AQI', 'range', 'level', 'PM2.5', 'PM10', 'CO', 'SO2', 'NO2', 'O3'])

            for data in dataList:
                csvWriter.writerow([
                    data['time_point'], data['aqi'], f'{data["min_aqi"]}~{data["max_aqi"]}', 
                    data['quality'], data['pm2_5'], data['pm10'], data['co'], data['so2'], 
                    data['no2'], data['o3']
                ])


    def _constructRequestPayload(self, city: str) -> str:
        Payload = {
            "appId": "3c9208efcfb2f5b843eec8d96de6d48a",
            "method": "GETMONTHDATA",
            "timestamp": int(time.time() * 1000),
            "clienttype": "WEB",
            "object": {
                "city": city
            }
        }
        secret = Payload['appId'] + Payload['method'] + str(Payload['timestamp']) + Payload['clienttype'] + json.dumps(Payload['object'], ensure_ascii=False, separators=(',', ':'))
        secret = hashlib.md5(secret.encode()).hexdigest()
        Payload['secret'] = secret

        Payload = base64.b64encode(
            json.dumps(
                Payload, 
                ensure_ascii=False, 
                separators=(',', ':')
            ).encode()
        ).decode()

        Payload = AESCipher(
            CipherKeysMapper.AES.get('Encrypt').get('key'), 
            CipherKeysMapper.AES.get('Encrypt').get('iv'), 
        ).encrypt(Payload)

        return Payload


    def _decryptResponse(self, response: str) -> list[dict[str, Any]]:
        response = base64.b64decode(response).decode()

        response = DESCipher(
            CipherKeysMapper.DES.get('Decrypt').get('key'), 
            CipherKeysMapper.DES.get('Decrypt').get('iv'), 
        ).decrypt(response)

        response = AESCipher(
            CipherKeysMapper.AES.get('Decrypt').get('key'), 
            CipherKeysMapper.AES.get('Decrypt').get('iv'), 
        ).decrypt(response)

        response = base64.b64decode(response).decode()

        response = json.loads(response)

        return response.get('result').get('data').get('items')
        

    async def fetch(self, session: aiohttp.ClientSession, city: str):
        async with self.semRequest:
            retryCount = 0
            while self.allowRequestEvent.is_set() and retryCount < 3:
                try:
                    async with session.post(
                        url="https://www.aqistudy.cn/historydata/api/historyapi.php",
                        data={
                            'hA4Nse2cT': self._constructRequestPayload(city)
                        }
                    ) as response:
                        html = await response.text()
                        dataList = self._decryptResponse(html)
                        async with self.dbLock:
                            self.storeData(city, dataList)
                            self.progress.update()
                    
                    break

                except Exception as e:
                    print(f"Collection Failed: {e}, Retry {retryCount + 1}/3")
                    retryCount += 1
                        

    async def _run(self):
        async with aiohttp.ClientSession(headers=self.header) as session:
            self.allowRequestEvent.set()
            tasks = [
                asyncio.create_task(self.fetch(session, city))
                for city in self.ciytList
            ]

            await asyncio.gather(*tasks)
    

    def start(self):
        self.loop.run_until_complete(self._run())


    def stop(self):
        self.allowRequestEvent.clear()
        self.loop.stop()
        self.loop.close()

    

if __name__ == '__main__':
    cnvd = AsyncAirQuality(ciytList=TARGETCITY)
    cnvd.start()

    
