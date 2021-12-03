"""
Sophos Endpoint Protection Application for Splunk Phantom.

> Custom Application built for Abanca

"""
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from sophosendpointprotection_consts import *

import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SophosEndpointProtectionConnector(BaseConnector):

    def __init__(self):
        # Call the BaseConnectors init first
        super(SophosEndpointProtectionConnector, self).__init__()
        self._state = {}
        self._base_url = None
        self._client_id = None
        self._client_secret = None
        self._JWT_token = None
        self._partner_token = None
        return

    def initialize(self):
        config = self.config()
        self._client_id = config[SOPHOS_CLIENT_ID].encode('utf-8')
        self._client_secret = config[SOPHOS_CLIENT_SECRET].encode('utf-8')
        self._state = self.load_state()
        self._JWT_token = self._state.get(SOPHOS_JWT_JSON, {}).get(SOPHOS_JWT_TOKEN)
        self._base_url = self._state.get(SOPHOS_PT_JSON, {}).get(SOPHOS_PT_API_HOSTS)
        self._partner_token = self._state.get(SOPHOS_PT_JSON, {}).get(SOPHOS_PT_TOKEN)
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method='get'):
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)
        # jwt_token = self._get_JWT_token()
        # partner_token = self._get_partner_token(jwt_token)

        # headers = {}
        # headers['Authorization'] = "Bearer {0}".format(jwt_token)
        # headers['X-Partner-ID'] = "{}".format(partner_token)
        
        # try:
        #     r = request_func(
        #                     url,
        #                     # auth=(username, password),  # basic authentication
        #                     headers=headers,
        #                     verify=config.get('verify_server_cert', False),
        #                     **kwargs)
        # except Exception as e:
        #     return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        # return self._process_response(r, action_result)
        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error connecting to server. Details: {0}').format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, action_result, endpoint, headers=None, params=None, data=None, json=None, method='get'):
        url = ("{0}{1}").format(self._base_url, endpoint)
        if headers is None:
            headers = {}
        jwt_json = self._state.get(SOPHOS_JWT_JSON, {})
        if not jwt_json.get(SOPHOS_JWT_TOKEN):
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return (action_result.set_status(), None)
        headers.update({'Authorization': ('Bearer {0}'.format(self._JWT_token)), 'X-Tenant-ID': '{0}'.format(self._partner_token), 'Content-Type': 'application/json'})

        ret_val, resp_json = self.make_rest_call(url, action_result, headers, params, data, json, method)          
        self.save_progress(("Response in JSON: {}".format(str(resp_json))))
        # self.save_progress(('Back to helper!!!'))
        msg = action_result.get_message()

        if msg and 'token is invalid' in msg or 'token has expired' in msg or 'ExpiredAuthenticationToken' in msg or 'authorization failed' in msg or 'access denied ' in msg:
            ret_val = self._get_token(action_result)
            headers.update({'Authorization': ('Bearer {0}').format(self._oauth_access_token)})
            ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json, method)

        self.save_progress(("Response in JSON: {}".format(str(resp_json))))
        
        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)
        else:
            return (
             phantom.APP_SUCCESS, resp_json)

    def _get_token(self, action_result, from_action=False):
        
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'scope': 'token',
            'grant_type': 'client_credentials'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        url = ("{0}".format(JWT_TOKEN_ENDPOINT))
        ret_val, resp_json = self._make_rest_call(url, action_result, headers=headers, data=data, method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self._state[SOPHOS_JWT_JSON] = resp_json
        self._JWT_token = resp_json[SOPHOS_JWT_TOKEN]


        # Getting the X-Tenant-ID
        data = {}
        headers = {'Authorization':'Bearer {}'.format(self._JWT_token), 'Accept': 'application/json'}
        url = ("{0}".format(WHOAMI_ENDPOINT))
        ret_val, resp_json = self._make_rest_call(url, action_result, headers=headers, data=data, method='get')
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self._state[SOPHOS_PT_JSON] = resp_json
        self._partner_token = resp_json[SOPHOS_PT_TOKEN]
        self._base_url = resp_json[SOPHOS_PT_API_HOSTS][SOPHOS_PT_DATA_REGION_URL]
        self.save_state(self._state)
        return phantom.APP_SUCCESS


    # """
    # Get JWT token each time a request is made.
    # TODO: Add a timer for 3600 seconds to avoid redundant requests to fetch the JWT token
    # """
    # def _get_JWT_token(self):
    #     self.save_progress("Getting JWT Token")
    #     headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    #     payload = 'grant_type=client_credentials&client_id={}&client_secret={}&scope=token'.format(self._client_id, self._client_secret)

    #     response = requests.request("POST", JWT_TOKEN_ENDPOINT, headers=headers, data = payload)
    #     #self.save_progress("Posting request for JWT")
    #     return json.loads(response.text)['access_token']

    """
    Get Partner Token.
    """
    # def _get_partner_token(self,jwt_token):
    #     self.save_progress("Getting the partner token")
    #     headers = {'Authorization': 'Bearer '.format(jwt_token)}
    #     payload = {}
    #     response = requests.request("POST", WHOAMI_ENDPOINT, headers=headers, data = payload)
    #     return json.loads(response.text)['id']

    """
    Handling Test Connectivity.
    Make a GET call to `\endpoints` endpoint.
    """
    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to the endpoint for test connectivity.")
        ret_val, response = self._make_rest_call('/endpoints', action_result, params=None, headers=None)
        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_endpoints(self, action_result, param):
        data = {}
        endpoint = None
        params = {}
        action_name = param.get('action_name')
        endpoint = ENDPOINTS_ENDPOINT
        if action_name=='list endpoints':
            if param['page_from_key'] is not None:
                params['pageFromKey'] = param['page_from_key']
            if param['page_size'] is not None:
                params['pageSize'] = param['page_size']
            if param['pageTotal'] is not None:
                params['pageTotal'] = param['page_total']
            if param['sort'] is not None:
                params['sort'] = param['sort']
            if param['health_status'] is not None:
                params['healthStatus'] = param['health_status']
            if param['type'] is not None:
                params['type'] = param['type']
            if param['tamper_protection_enabled'] is not None:
                params['tamperProtectionEnabled'] = param['tamper_protection_enabled']
            if param['lockdown_status'] is not None:
                params['lockdownStatus'] = param['lockdown_status']
            if param['last_seen_before'] is not None:
                params['lastSeenBefore'] = param['last_seen_before']
            if param['lastSeenAfter'] is not None:
                params['lastSeenAfter'] = param['last_seen_after']
            if param['ids'] is not None:
                params['ids'] = param['ids']
            if param['fields'] is not None:
                params['fields'] = param['fields']
            if param['view'] is not None:
                params['view'] = param['view']
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='get')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            for item in response['items']:
                action_result.add_data(item)    
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['total_number_of_items'] = len(response['items'])
            return phantom.APP_SUCCESS

        elif action_name=='get individual endpoint':
            endpointId = params['endpointid']
            if params['fields'] is not None:
                param['fields'] = param['fields'].split(",")
            if params['view'] is not None:
                param['view'] = params['view']

            endpoint = "{}{}".format(endpoint,INDIVIDUAL_ENDPOINT.format(str(endpointId)))  
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='get')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['total_number_of_items'] = 1
            return phantom.APP_SUCCESS

        elif action_name=='delete endpoint':
            endpointId = params['endpointid']
            endpoint = "{}{}".format(endpoint,INDIVIDUAL_ENDPOINT.format(str(endpointId)))
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='delete')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            action_result.add_data({"endpoint_deleted":"true"})
            summary = action_result.update_summary({})
            summary['total_endpoints_deleted'] = 1
            return phantom.APP_SUCCESS
            

    def _list_endpoints(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'list endpoints'
        ret_val = self._handle_detects(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _delete_endpoint(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'delete endpoint'
        ret_val = self._handle_detects(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()    
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_individual_endpoint(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'get individual endpoint'
        ret_val = self._handle_detects(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status() 
        return action_result.set_status(phantom.APP_SUCCESS)



    def _handle_check_updates(self, action_result, param):
        data = {}
        endpoint = None
        params = {}
        action_name = param.get('action_name')
        endpointId = param.get('endpointid')
        endpoint = UPDATE_CHECK_ENDPOINT.format(endpointId)    
        if action_name == 'check updates':
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='get')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['number_of_endpoints_checked'] = 1 
            return phantom.APP_SUCCESS


    def _check_updates(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'check updates'
        ret_val = self._handle_detects(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tamperprotection_settings(self, action_result, param):
        data = {}
        endpoint = None
        params = {}
        action_name = param.get('action_name')
        endpointId = param.get('endpointid')
        endpoint = TAMPER_PROTECTION_ENDPOINT.format(endpointId)    
        if action_name=='get settings':
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='get')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['number_of_endpoints_tp_settings_recieved'] = 1
            summary['number_of_times_passwords_changed'] = len(response['previous_passwords']) 
            return phantom.APP_SUCCESS
        elif action_name=='update settings':
            data['enabled'] = param.get('enabled', 'true')
            data['regeneratePassword'] = param.get('regeneratepassword','true')
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='post')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['number_of_endpoints_tp_settings_updated'] = 1
            return phantom.APP_SUCCESS

    def _update_tamperprotection_settings(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'update settings'
        ret_val = self._handle_tamperprotection_settings(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)


    def _get_tamperprotection_settings(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        endpointid = param['endpointid']
        ret_val, response = self._handle_tamperprotection_settings(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scans(self, action_result, param):
        data = {}
        endpoint = None
        params = {}
        action_name = param.get('action_name')
        endpointId = param.get('endpointid')
        endpoint = SCAN_ENDPOINT.format(endpointId)
        if action_name == 'perform scan':
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params, data=json.dumps(data), method='post')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            action_result.add_data(response)
            action_result.set_status(phantom.APP_SUCCESS,SOPHOS_OKAY_MESSAGE)    
            summary = action_result.update_summary({})
            summary['number_of_scans_performed'] = 1
            return action_result.set_status(phantom.APP_SUCCESS)

    def _perform_scan(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        param['action_name'] = 'perform scan'
        ret_val = self._handle_scans(action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_endpoints':
            ret_val = self._list_endpoints(param)

        elif action_id == 'get_individual_endpoint':
            ret_val = self._get_individual_endpoint(param)    

        elif action_id == 'delete_endpoint':
            ret_val = self._delete_endpoint(param)

        elif action_id == 'check_updates':
            ret_val = self._check_updates(param)

        elif action_id == 'tamper_protection_switch':
            ret_val = self._update_tamperprotection_settings(param)

        elif action_id == 'get_tamper_protection_settings':
            ret_val = self._get_tamperprotection_settings(param)

        elif action_id == 'perform_scan':
            ret_val = self._perform_scan(param)
        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = SophosEndpointProtectionConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SophosEndpointProtectionConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)