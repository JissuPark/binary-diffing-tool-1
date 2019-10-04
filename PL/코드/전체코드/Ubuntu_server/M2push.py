import requests
import json


class M2push:
    username = ''
    api_key = ''
    url = ''

    type = {
        'win': 'peinfo',
        'linux': 'fullinfo',
    }

    def send(self, data, type):
        """
        :param data: Report dictionary to send M2LAB server
        :type data: dict
        :param type: Server type(linux or win)
        :type type: str
        :return: True(success) or False(failed)
        """

        url = self.url + '/api/report_server/' + self.type[type] + '/' + self.username + '/' + self.api_key

        headers = {'Content-type': 'application/json'}

        rsp = requests.post(url, json=data, headers=headers)

        result = json.loads(rsp.text)

        if result['success'] == 'true':
            return True
        else:
            print("ERROR CODE: ", result['code'])
            print("MESSAGE: ", result['message'] if "message" in result else "None")
            return False

    def __init__(self, url, username, api_key):
        """
        :param url: M2LAB server url(ex http://127.0.0.1:3000)
        :type url: str
        :param username: M2LAB system account username
        :type username: str
        :param api_key: M2LAB system account apiKey
        :type api_key: str
        """
        self.url = url
        self.username = username
        self.api_key = api_key
        
