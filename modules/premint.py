import ssl
import time
from re import findall
import cloudscraper
from capmonster_python import RecaptchaV2Task
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
import threading
from utils import get_tasks
from data.config import RETRY_AMOUNT
from utils.logger import PremintLogger
import requests
from bs4 import BeautifulSoup
import re
import json
import urllib3
import urllib.parse
import getpass
from random import randint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# https://github.com/senluet/  CHECK MY GIT


def main():
    tasks = get_tasks("./tasks.csv")
    tasks_count = len(tasks)
    i = 1
    for task in tasks:
        threading.Thread(
            target=Premint(
                task=task,
                task_num=i,
                tasks_count=tasks_count,
                proxy=task["account_proxy"]
            ).start_task
        ).start()
        i += 1

class Premint:
    def __init__(self, task: dict, task_num: int, tasks_count: int, proxy: str):
        self.logger = PremintLogger(
            module="premint",
            account_name=task["account_name"],
            task=self._beautify_task_number(task_num, tasks_count),
            total_tasks=tasks_count
        )

        self.raffle_url = task["raffle_url"]
        self.email = task["email"]
        self.account: LocalAccount = task["account"]
        self.twitter_username = task["twitter_username"]
        self.twitter_pass = task["twitter_pass"]
        self.twitter_email = task["twitter_email"]
        self.proxy = task["account_proxy"]

        self.session = requests.session()
        self.csrf = None
        self.captcha_required = None
        self.registered = None

    def start_task(self):
        self.session = requests.session()
        self.proxies = {'https': self.proxy}
        self.session.proxies.update(self.proxies)
        self.session.headers.update({
            "User-Agent": "'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://www.premint.xyz/",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1"
        })
        try:
            if self._get_csrf_token():
                if self._register():
                    if self._login():
                        if self._submit_entry():
                            return
        except Exception as err:
            self.logger.error(f"Unknown error while starting tasks: {err}")
            raise err
        finally:
            self.session.close()

    def getTokens(self):
        user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                      'Referer': 'https://twitter.com/sw.js'}
        url_base = "https://twitter.com/home?precache=1"
        r = requests.get(url_base, verify=False, headers=user_agent, proxies=self.proxies)
        soup = BeautifulSoup(r.text, "html.parser")
        js_with_bearer = ""
        for i in soup.find_all('link'):
            if i.get("href").find("/main") != -1:
                js_with_bearer = i.get("href")

        guest_token = re.findall(r'"gt=\d{19}', str(soup.find_all('script')[-1]), re.IGNORECASE)[0].replace("\"gt=", "")
        user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                      'Referer': 'https://twitter.com/sw.js'}
        r = requests.get(js_with_bearer, verify=False, headers=user_agent, proxies=self.proxies)
        bearer = re.findall(r'",[a-z]="(.*)",[a-z]="\d{8}"', r.text, re.IGNORECASE)[0].split("\"")[-1]

        rt_path = re.search(r'queryId:"(.+?)",operationName:"Retweeters"', r.text).group(1).split('"')[-1]
        viewer_path = re.search(r'queryId:"(.+?)",operationName:"Viewer"', r.text).group(1).split('"')[-1]
        authorization_bearer = "Bearer %s" % bearer
        return authorization_bearer, guest_token, rt_path, viewer_path


    def login(self, username, password, email_tw, adress):
        authorization_bearer, guest_token, rt_path, viewer_path = self.getTokens()
        self.authorization_bearer = authorization_bearer
        self.guest_token = guest_token
        self.rt_path = rt_path
        self.viewer_path = viewer_path
        try:
            with open(f'cook/{adress}.txt', 'r') as file:
                data = file.read()
            cookie = findall("'Cookie': '(.*?)'", data)[0]
            csrf_token = findall("'x-csrf-token': '(.*?)'", data)[0]
            user_agent_for_tw = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                                 'Cookie': cookie, 'x-csrf-token': csrf_token}
            auth_token = ''
            return auth_token, user_agent_for_tw
        except:

            url_flow_1 = "https://twitter.com/i/api/1.1/onboarding/task.json?flow_name=login"
            url_flow_2 = "https://twitter.com/i/api/1.1/onboarding/task.json"

            data = {'': ''}
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer}
            r = requests.post(url_flow_1, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
            flow_token = json.loads(r.text)['flow_token']

            data = {'flow_token': flow_token, "subtask_inputs": []}
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer}
            r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
            flow_token = json.loads(r.text)['flow_token']

            data = {"flow_token": flow_token, "subtask_inputs": [{"subtask_id": "LoginEnterUserIdentifierSSO",
                                                                  "settings_list": {"setting_responses": [
                                                                      {"key": "user_identifier", "response_data": {
                                                                          "text_data": {"result": username}}}],
                                                                                    "link": "next_link"}}]}
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer}
            r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
            flow_token = json.loads(r.text)['flow_token']

            if (json.loads(r.text)['subtasks'][0]['subtask_id'] == "LoginEnterAlternateIdentifierSubtask"):
                data = {"flow_token": flow_token, "subtask_inputs": [
                    {"subtask_id": "LoginEnterAlternateIdentifierSubtask",
                     "enter_text": {"text": email_tw, "link": "next_link"}}]}
                user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                              'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                              'Content-Type': 'application/json', 'Authorization': authorization_bearer}
                r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
                flow_token = json.loads(r.text)['flow_token']

            data = {"flow_token": flow_token, "subtask_inputs": [
                {"subtask_id": "LoginEnterPassword", "enter_password": {"password": password, "link": "next_link"}}]}
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer}
            r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
            flow_token = json.loads(r.text)['flow_token']
            user_id = json.loads(r.text)['subtasks'][0]['check_logged_in_account']['user_id']

            data = {"flow_token": flow_token, "subtask_inputs": [{"subtask_id": "AccountDuplicationCheck",
                                                                  "check_logged_in_account": {
                                                                      "link": "AccountDuplicationCheck_false"}}]}
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer}
            r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data), proxies=self.proxies)
            auth_token = r.cookies['auth_token']
            user_agent_for_tw = {}
            return auth_token, user_agent_for_tw

    def getCSRFToken(self, guest_token, auth_token, authorization_bearer, raffle_url, oauth_token, action_number, adress):
        try:
            with open(f'cook/{adress}.txt', 'r') as file:
                data = file.read()
            cookie = findall("'Cookie': '(.*?)'", data)[0]
            csrf_token = findall("'x-csrf-token': '(.*?)'", data)[0]
            user_agent_for_tw = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                                 'Cookie': cookie, 'x-csrf-token': csrf_token}
            twitter_task2 = requests.get(
                'https://api.twitter.com/oauth/authenticate?oauth_token=' + oauth_token + '&oauth_callback=https://www.premint.xyz/accounts/twitter/login/callback/',
                timeout=15, headers=user_agent_for_tw, proxies=self.proxies)
            authenticity_token = findall('authenticity_token" value="(.*?)"', str(twitter_task2.text))[0]
            data = {
                "authenticity_token": authenticity_token,
                "redirect_after_login": "https://api.twitter.com/oauth/authorize?oauth_token=" + oauth_token,
                "oauth_token": oauth_token
            }
            r = requests.post('https://api.twitter.com/oauth/authorize', verify=False, data=data,
                              headers=user_agent_for_tw, timeout=15, proxies=self.proxies)
            oauth_verifier = findall('oauth_verifier=(.*?)"', str(r.text))[0]
            return csrf_token, user_agent_for_tw, oauth_verifier
        except:
            payload = '{"withCommunitiesMemberships":true,"withCommunitiesCreation":true,"withSuperFollowsUserFields":true}'
            url_session_token = "https://twitter.com/i/api/graphql/%s/Viewer?variables=%s" % (
            self.viewer_path, urllib.parse.quote_plus(payload))
            cookie = "ct0=%s; auth_token=%s" % (guest_token, auth_token)
            user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                          'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                          'Content-Type': 'application/json', 'Authorization': authorization_bearer, 'Cookie': cookie}
            r = requests.get(url_session_token, verify=False, headers=user_agent, proxies=self.proxies)
            csrf_token = r.cookies['ct0']
            cookie = "ct0=%s; auth_token=%s" % (csrf_token, auth_token)
            user_agent_for_tw = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                                 'Referer': 'https://twitter.com/sw.js', 'X-Guest-Token': guest_token,
                                 'Content-Type': 'application/json', 'Authorization': authorization_bearer,
                                 'Cookie': cookie, 'x-csrf-token': csrf_token}
            r = requests.get('https://twitter.com/i/js_inst?c_name=ui_metrics', verify=False, headers=user_agent_for_tw, proxies=self.proxies)
            twitter_sess_token = findall('_twitter_sess=(.*?);', str(r.headers))[0]
            cookie = "ct0=%s; auth_token=%s; _twitter_sess=%s" % (csrf_token, auth_token, twitter_sess_token)
            user_agent_for_tw = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                                 'Cookie': cookie, 'authorization': authorization_bearer, 'x-csrf-token': csrf_token}
            with open(f'cook/{adress}.txt', 'w') as file:
                file.write(str(user_agent_for_tw))
            if action_number == '1':
                twitter_task2 = requests.get(
                    'https://api.twitter.com/oauth/authenticate?oauth_token=' + oauth_token + '&oauth_callback=https://www.premint.xyz/accounts/twitter/login/callback/',
                    timeout=15, headers=user_agent_for_tw, proxies=self.proxies)
                authenticity_token = \
                findall('authenticity_token" type="hidden" value="(.*?)"', str(twitter_task2.text))[0]
                data = {
                    "authenticity_token": authenticity_token,
                    "redirect_after_login": "https://api.twitter.com/oauth/authorize?oauth_token=" + oauth_token,
                    "oauth_token": oauth_token
                }
                r = requests.post('https://api.twitter.com/oauth/authorize', verify=False, data=data,
                                  headers=user_agent_for_tw, timeout=15, proxies=self.proxies)
                oauth_verifier = findall('oauth_verifier=(.*?)"', str(r.text))[0]
                return csrf_token, user_agent_for_tw, oauth_verifier
            else:
                return user_agent_for_tw

    def follow(self, adress, profile_url):
        with open(f'cook/{adress}.txt', 'r') as file:
            data = file.read()
        cookie = findall("'Cookie': '(.*?)'", data)[0]
        csrf_token = findall("'x-csrf-token': '(.*?)'", data)[0]
        bearer_token = findall("'authorization': '(.*?)'", data)[0]
        user_agent_for_tw = {
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Origin': 'https://mobile.twitter.com',
            'Referer': 'https://mobile.twitter.com/',
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7',
            'Cookie': cookie,
            'x-csrf-token': csrf_token,
        }
        r = requests.get('https://twitter.com/home', verify=False, headers=user_agent_for_tw, proxies=self.proxies)
        url_to_get_query_ids = BeautifulSoup(r.text, 'lxml') \
            .find_all('link',
                      {'rel': 'preload', 'as': 'script', 'crossorigin': 'anonymous'})[-1] \
            .get('href')
        r = requests.get(url_to_get_query_ids,
                         verify=False, headers=user_agent_for_tw, proxies=self.proxies)
        queryIdforUserByScreenName = r.text.split('",operationName:'
                                                  '"UserByScreenName')[0] \
            .split('"')[-1]

        user_agent_for_tw.update(
            {
                'authorization': bearer_token,
                'content-type': 'application/x-www-form-urlencoded'
            })

        r = requests.get(f'https://mobile.twitter.com/i/api/graphql/'
                         f'{queryIdforUserByScreenName}'
                         + '/UserByScreenName?variables='
                           '{"screen_name":"' + profile_url
                         .replace('@', '') + '",'
                                             '"withSafetyModeUserFields":true,'
                                             '"withSuperFollowsUserFields":true}',
                         headers=user_agent_for_tw,
                         verify=False, proxies=self.proxies)
        rest_id = str(json.loads(r.text)['data']['user']['result']['rest_id'])
        r = requests.post('https://mobile.twitter.com/i/api/1.1/'
                          'friendships/create.json',
                          data='include_profile_interstitial_type=1&'
                               'include_blocking=1&'
                               'include_blocked_by=1&'
                               'include_followed_by=1&'
                               'include_want_retweets=1&'
                               'include_mute_edge=1&'
                               'include_can_dm=1&'
                               'include_can_media_tag=1&'
                               'include_ext_has_nft_avatar=1&'
                               'skip_status=1&'
                               'user_id=' + rest_id,
                          headers=user_agent_for_tw,
                          verify=False, proxies=self.proxies)

    def re_like(self, adress, twit_url):
        with open(f'cook/{adress}.txt', 'r') as file:
            data = file.read()
        cookie = findall("'Cookie': '(.*?)'", data)[0]
        csrf_token = findall("'x-csrf-token': '(.*?)'", data)[0]
        bearer_token = findall("'authorization': '(.*?)'", data)[0]
        user_agent_for_tw = {
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Origin': 'https://mobile.twitter.com',
            'Referer': 'https://mobile.twitter.com/',
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7',
            'Cookie': cookie,
            'x-csrf-token': csrf_token,
        }
        r = requests.get('https://twitter.com/home', verify=False, headers=user_agent_for_tw, proxies=self.proxies)
        url_to_get_query_ids = BeautifulSoup(r.text, 'lxml') \
            .find_all('link',
                      {'rel': 'preload', 'as': 'script', 'crossorigin': 'anonymous'})[-1] \
            .get('href')
        r = requests.get(url_to_get_query_ids,
                         verify=False, headers=user_agent_for_tw, proxies=self.proxies)
        queryIdforLike = r.text.split('",operationName:"FavoriteTweet')[0] \
            .split('"')[-1]
        queryIdforRetweet = r.text.split('",operationName:"CreateRetweet')[0] \
            .split('"')[-1]
        queryIdforUserByScreenName = r.text.split('",operationName:'
                                                  '"UserByScreenName')[0] \
            .split('"')[-1]
        user_agent_for_tw.update(
            {
                'authorization': bearer_token
            })
        r = requests.post(f'https://mobile.twitter.com/i/api/graphql/'
                          f'{queryIdforLike}/FavoriteTweet',
                          json={"variables":
                                    {"tweet_id": twit_url},
                                "queryId": queryIdforRetweet},
                          verify=False, headers=user_agent_for_tw, proxies=self.proxies)
        r = requests.post(f'https://twitter.com/i/api/graphql/'
                          f'{queryIdforRetweet}/CreateRetweet',
                          json={"variables":
                                    {"tweet_id": twit_url,
                                     "dark_request": False},
                                "queryId": queryIdforRetweet},
                          verify=False, headers=user_agent_for_tw, proxies=self.proxies)

    def _get_csrf_token(self):
        for _ in range(RETRY_AMOUNT):
            try:
                self.logger.info("Initializing session...")
                with self.session.get("https://www.premint.xyz/login/", timeout=15) as response:
                    if response.ok:
                        self.session.headers.update({"x-csrftoken": response.cookies["csrftoken"]})
                        self.cf_bm = findall('__cf_bm=(.*?);', str(response.headers))[0]
                        self.csrf_token_premint = response.cookies["csrftoken"]
                        return True
                    else:
                        self.logger.error(f"Unknown status code while initializing session [{response.status_code}]")
            except Exception as err:
                self.logger.error(f"Error initializing session: {err}")

            time.sleep(randint(3,10))

        return False

    def _register(self):
        for _ in range(RETRY_AMOUNT):
            try:
                self.session.headers.update(
                    {
                        "referer": "https://www.premint.xyz/v1/login_api/",
                        "content-type": "application/x-www-form-urlencoded; charset=UTF-8"
                    }
                )
                data = f"username={self.account.address.lower()}"

                self.logger.info("Registering account...")
                with self.session.post("https://www.premint.xyz/v1/signup_api/", data=data, timeout=15) as response:
                    if response.ok:
                        return True
                    else:
                        self.logger.error(f"Unknown status code while registering account [{response.status_code}]")
            except Exception as err:
                self.logger.error(f"Error registering account: {err}")

            time.sleep(randint(3,10))

        return False

    def _login(self):
        for _ in range(RETRY_AMOUNT):
            try:
                for _ in range(RETRY_AMOUNT):
                    if self._get_nonce():
                        message = encode_defunct(text=self._get_message_to_sign())
                        signed_message = self.account.sign_message(message)
                        signature = signed_message["signature"].hex()
                        data = f"web3provider=metamask&address={self.account.address.lower()}&signature={signature}"

                        self.logger.info("Login in account...")
                        with self.session.post("https://www.premint.xyz/v1/login_api/", data=data,
                                               timeout=15) as response:
                            if response.ok:
                                if response.json()["success"]:
                                    self.logger.success(f"Successfully logged in account!")
                                    return True
                                else:
                                    self.logger.error(f"Error login: {response.text} [{response.status_code}]")
                            else:
                                self.logger.error(f"Unknown status code while login [{response.status_code}]")
                    return False

            except Exception as err:
                self.logger.error(f"Error login: {err}")

            time.sleep(randint(3,10))

        return False

    def _update_csrf_token(self):
        for _ in range(RETRY_AMOUNT):
            try:
                with self.session.get(self.raffle_url, timeout=15) as response2:
                    if "Registered" in response2.text:
                        return True
                    else:
                        self.logger.info("Getting csrf token...")
                        with self.session.get(self.raffle_url, timeout=15) as response:
                            try:
                                self.profile_url = findall('<a class="c-base-1 strong-700 text-underline" href="https://twitter.com/(.*?)"', str(response.text))[0]
                            except:
                                self.profile_url = False
                            try:
                                self.profile_url_2 = findall('<a class="c-base-1 strong-700 text-underline" href="https://twitter.com/(.*?)"', str(response.text))[1]
                            except:
                                self.profile_url_2 = False
                            try:
                                self.profile_url_3 = findall('<a class="c-base-1 strong-700 text-underline" href="https://twitter.com/(.*?)"', str(response.text))[2]
                            except:
                                self.profile_url_3 = False
                            try:
                                self.profile_url_4 = findall('<a class="c-base-1 strong-700 text-underline" href="https://twitter.com/(.*?)"', str(response.text))[3]
                            except:
                                self.profile_url_4 = False
                            try:
                                self.profile_url_5 = findall('<a class="c-base-1 strong-700 text-underline" href="https://twitter.com/(.*?)"', str(response.text))[4]
                            except:
                                self.profile_url_5 = False
                            try:
                                self.twit_url = findall('<a href="https://twitter.com/user/status/(.*?)"', str(response.text))[0]
                            except:
                                self.twit_url = False
                            try:
                                self.twit_url_2 = findall('<a href="https://twitter.com/user/status/(.*?)"', str(response.text))[1]
                            except:
                                self.twit_url_2 = False
                            try:
                                self.twit_url_3 = findall('<a href="https://twitter.com/user/status/(.*?)"', str(response.text))[2]
                            except:
                                self.twit_url_3 = False
                            try:
                                self.twit_url_4 = findall('<a href="https://twitter.com/user/status/(.*?)"', str(response.text))[3]
                            except:
                                self.twit_url_4 = False
                            try:
                                self.csrf = findall('csrfmiddlewaretoken" value="(.*?)"', str(response.text))[0]
                                if response.ok:
                                    if "0x" in response.text:
                                        self.captcha_required = False
                                    else:
                                        self.captcha_required = False

                                    if "Registered" in response.text:
                                        self.registered = True
                                    else:
                                        self.registered = False
                                    return True
                                else:
                                    self.logger.error(f"Unknown status code while getting csrf token [{response.status_code}]")
                            except:
                                self.logger.error(f"Error getting csrf token: , may be twitter not connected, try connect twitter...")
                                if "process=connect" in response.text:
                                    try:
                                        with self.session.get(
                                                'https://www.premint.xyz/accounts/twitter/login/?process=connect&next=' +
                                                self.raffle_url.split('.xyz')[1], timeout=15,
                                                allow_redirects=False) as response1:
                                                oauth_token = findall('oauth_token=(.*?)&', str(response1.headers['Location']))[0]
                                                action_number = '1'
                                                adress = self.account.address.lower()
                                                csrf_token, self.user_agent_for_tw, oauth_verifier = self.getCSRFToken(self.guest_token, auth_token, self.authorization_bearer, self.raffle_url, oauth_token, action_number, adress)
                                                premint_task = self.session.get(
                                                    'https://www.premint.xyz/accounts/twitter/login/callback/?oauth_token=' + oauth_token + '&oauth_verifier=' + oauth_verifier,
                                                    timeout=15)
                                    except:
                                        username = self.twitter_username
                                        password = self.twitter_pass
                                        email_tw = self.twitter_email
                                        if (username is not None):
                                            password = password
                                            if password is None:
                                                password = getpass.getpass(prompt='Password: ')
                                            auth_token, user_agent_for_tw = self.login(username, password, email_tw, adress)
                                            with self.session.get('https://www.premint.xyz/accounts/twitter/login/?process=connect&next=' + self.raffle_url.split('.xyz')[1], timeout=15, allow_redirects=False) as response:
                                                oauth_token = findall('oauth_token=(.*?)&', str(response.headers['Location']))[0]
                                                action_number = '1'
                                                adress = self.account.address.lower()
                                                try:
                                                    with open(f'cook/{adress}.txt', 'r') as file:
                                                        data = file.read()
                                                    cookie = findall("'Cookie': '(.*?)'", data)[0]
                                                    csrf_token = findall("'x-csrf-token': '(.*?)'", data)[0]
                                                except:
                                                    csrf_token, self.user_agent_for_tw, oauth_verifier = self.getCSRFToken(
                                                        self.guest_token, auth_token, self.authorization_bearer, self.raffle_url,
                                                        oauth_token, action_number, adress)
                                                    self.session.get('https://www.premint.xyz/accounts/twitter/login/callback/?oauth_token=' + oauth_token + '&oauth_verifier=' + oauth_verifier, timeout=15)
                                        else:
                                            self.logger.error("Username is empty")
                                else:
                                    return True
            except Exception as err:
                self.logger.error(f"Error getting csrf token: {err}")

            time.sleep(randint(3,10))

        return False

    def _submit_entry(self):
        for _ in range(RETRY_AMOUNT):
            if self._update_csrf_token():
                pass
            else:
                return

            if self.registered:
                self.logger.success(f"Already registered for raffle")
                return True

            body = f"csrfmiddlewaretoken={self.csrf}" \
                   "&custom_field=yes" \
                   "&params_field={}" \
                   f"&minting_wallet={self.account.address.lower()}" \
                   "&registration-form-submit="

            if self.captcha_required:
                while True:
                    try:
                        #g_recaptcha_response = self._solve_captcha()
                        self.logger.info(f"Successfully solved captcha")

                        #body += f"&captcha={g_recaptcha_response}"
                        break

                    except Exception as err:
                        self.logger.error(f"Error solving captcha: {err}")

            try:
                with self.session.get(self.raffle_url, timeout=15) as response2:
                    if "Registered" in response2.text:
                        self.logger.success(f"You already have been registered to raffle!")
                        return True
                    else:
                        try:
                            adress = self.account.address.lower()
                            self.logger.info("Follow, Like & Retweet...")
                            try:
                                if self.profile_url:
                                    self.follow(adress, self.profile_url)
                                if self.profile_url_2:
                                    self.follow(adress, self.profile_url_2)
                                if self.profile_url_3:
                                    self.follow(adress, self.profile_url_3)
                                if self.profile_url_4:
                                    self.follow(adress, self.profile_url_4)
                                if self.profile_url_5:
                                    self.follow(adress, self.profile_url_5)
                                if self.twit_url:
                                    self.re_like(adress, self.twit_url)
                                if self.twit_url_2:
                                    self.re_like(adress, self.twit_url_2)
                                if self.twit_url_3:
                                    self.re_like(adress, self.twit_url_3)
                                if self.twit_url_4:
                                    self.re_like(adress, self.twit_url_4)
                            except:
                                username = self.twitter_username
                                password = self.twitter_pass
                                email_tw = self.twitter_email

                                self.login(username, password, email_tw, adress)

                                if self.profile_url:
                                    self.follow(adress, self.profile_url)
                                if self.profile_url_2:
                                    self.follow(adress, self.profile_url_2)
                                if self.twit_url:
                                    self.re_like(adress, self.twit_url)
                                if self.twit_url_2:
                                    self.re_like(adress, self.twit_url_2)
                        except Exception as err:
                            self.logger.error(f"Error: {err} Like or Retweet, please wait...")

                        self.logger.info("Submitting raffle entry...")
                        with self.session.post(self.raffle_url, data=body, timeout=15) as response:
                            if response.status_code == 200:
                                time.sleep(3)
                                with self.session.get(self.raffle_url, timeout=15) as response2:
                                    if "Registered" in response2.text:
                                        self.logger.success(f"You have been registered to raffle!")
                                        return True
                                    else:
                                        self.logger.error(f"Error submitting entry [{response.url}]")
                            else:
                                self.logger.error(f"Unknown status code while submitting entry [{response.status_code}]")
            except Exception as err:
                self.logger.error(f"Retrying entry {err}")
            time.sleep(randint(3,10))

        return False

    def _get_message_to_sign(self) -> str:

        return "Welcome to PREMINT!\n\n" \
               "Signing is the only way we can truly know \n" \
               "that you are the owner of the wallet you \n" \
               "are connecting. Signing is a safe, gas-less \n" \
               "transaction that does not in any way give \n" \
               "PREMINT permission to perform any \n" \
               "transactions with your wallet.\n\n" \
               f"Wallet address:\n{self.account.address.lower()}\n\n" \
               f"Nonce: {self.nonce}"

    def _get_nonce(self):
        try:
            with self.session.get("https://www.premint.xyz/v1/login_api/", timeout=15) as response:
                if response.ok:
                    self.nonce = response.json()["data"]
                    return True
                else:
                    self.logger.error(f"Unknown status code while getting nonce [{response.status_code}]")
        except Exception as err:
            self.logger.error(f"Error getting nonce: {err}")

        return False

    def _solve_captcha(self) -> str:
        self.logger.info("Solving captcha")

        capmonster = RecaptchaV2Task('API_KEY')
        task_id = capmonster.create_task(self.raffle_url, "")
        result = capmonster.join_task_result(task_id)

        return result.get("gRecaptchaResponse")

    @staticmethod
    def _make_scraper():
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    @staticmethod
    def _beautify_task_number(task_num: int, tasks_count: int) -> str:
        return "0" * (len(str(tasks_count)) - len(str(task_num))) + str(task_num)


if __name__ == "__main__":
    main()

