#!/usr/bin/python

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION= '''
----
'''

RETURN = '''

'''

from ansible.module_utils.basic import *


def run_module():
    ##The allowed module argument
    module_args = dict(
        taniumhostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        mw_name=dict(type='str', required=True),
        patch_start_time=dict(type='str', required=True),
        patch_end_time=dict(type='str', required=True)
    )
    # setting up the dictionary of the return
    result = dict(
        changed=False,
        message='',
        patch_output= [ ]
    )
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    ##Gathering the variables
    username = module.params['username']
    password = module.params['password']
    mw_name = module.params['mw_name']
    patch_start_time=module.params['patch_start_time']
    patch_end_time=module.params['patch_end_time']
    hostname=module.params['taniumhostname']
    
    # Checking if the maitenance window already exists with the same name
    allmw = get_maintenancewindow(hostname, username, password)["maintenanceWindows"]
    mw_state = [x for x in allmw if x['name'] == mw_name]
    if mw_state:
        result['message'] = 'Maintenance window with the same name already exist.'
        result['changed'] = False
        result['patch_output'] = mw_state
    else:
        print("Creating Maintenance Window with the given attributes")
        mw_state = new_maintenancewindow(hostname, username, password, mw_name, patch_start_time, patch_end_time)
        result['message'] = 'Maintenance Window created with the given attributes'
        result['changed'] = True
        result['patch_output'] = mw_state

    module.exit_json(**result)

def get_loginsession(username, password, hostname):
    userobj = {
        "username": username,
        "password": password
    }
    juserobj = json.dumps(userobj)
    # headers = {
    #     'Content-Type': 'application/json'
    # }
    api = "/api/v2/session/login"
    uri = "https://" + hostname + api
    r = requests.get(uri, verify=False, data=juserobj)
    jsonobj = r.json()
    sessionbj = jsonobj["data"]["session"]
    return sessionbj

def get_maintenancewindow(hostname, username, password):
    sessionID = get_loginsession(username, password, hostname)
    session = {'session': sessionID }
    api = "/plugin/products/patch/v1/maintenance-windows"
    uri = "https://" + hostname + api
    r = requests.get(uri, verify=False, headers=session)
    jsonobj = r.json()
    return jsonobj

def new_maintenancewindow(hostname, username, password, name, patch_start_time, patch_end_time):
    sessionID = get_loginsession(username, password, hostname)
    api = "/plugin/products/patch/v1/maintenance-windows"
    uri = "https://" + hostname + api
    body = {
        "name": name,
        "osType": "windows",
        "repeatEvery": None,
        "useTaniumClientTimeZone": 'false',
        "repeatType": None,
        "startTime": patch_start_time,
        "endTime": patch_end_time
    }
    jobj = json.dumps(body)
    headers = {
    'Content-Type': 'application/json',
    'session': sessionID
    }
    r =	requests.post(uri, verify=False, data=jobj, headers=headers)
    jsonobj = r.json()
    return jsonobj

def main():
    run_module()

if __name__ == '__main__':
    main()
