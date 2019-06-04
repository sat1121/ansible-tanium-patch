#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION= '''
----
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from ansible.module_utils.basic import *

def run_module():
  ## The allowed module argument
    module_args = dict(
        taniumhostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        mw_name=dict(type='str', required=True),
        computergroupID=dict(type='str', required=True)
    )
    result = dict(
        changed=False,
        message='',
        patch_output= [ ]
    )
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    ## Gather the variables
    username = module.params['username']
    password = module.params['password']
    mw_name = module.params['mw_name']
    hostname = module.params['taniumhostname']
    computergroupID = module.params['computergroupID']

    #Checking if the maintenance window with the name exist
    allmw = get_maintenancewindow(hostname, username, password)["maintenanceWindows"]
    mw_state = [x for x in allmw if x['name'] == mw_name]
    if mw_state is None:
        module.fail_json(msg="Dont see any maintenance windo with this name. Erroring out")
    mwID = mw_state[0]["id"]
    ## Getting Maintenance window enforcement id
    sessionID = get_loginsession(username, password, hostname)
    session = {'session': sessionID }
    uri = "https://" + hostname + "/plugin/products/patch/v1/maintenance-windows/" + str(mwID)
    r = requests.get(uri, verify=False, headers=session)
    mw_enforcements = r.json()["enforcements"]
    for mw_enforcement in mw_enforcements:
        ##comparing the enforcement list to verify of the computer group already added.
        if str(mw_enforcement['taniumGroupId']) == str(computergroupID):
            result['message'] = 'Looks like the enforcement already exists for the MW and computer group'
            result['changed'] = False
            result['patch_output'] = mw_enforcement
            break
    else:
        mw_enf_state = new_patchenforcement(hostname, username, password, mwID, computergroupID)
        result['message'] = 'New Enforcements created with the given attributes.'
        result['changed'] = True
        result['patch_output'] = mw_enf_state
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

def get_patchenforcement(hostname, username, password):
    sessionID = get_loginsession(username, password, hostname)
    session = {'session': sessionID }
    api = '/plugin/products/patch/v1/enforcements'
    uri = "https://" + hostname + api
    r = requests.get(uri, verify=False, headers=session)
    jsonobj = r.json()
    return jsonobj

def new_patchenforcement(hostname, username, password, mwID, computergroupID):
    sessionID = get_loginsession(username, password, hostname)
    api = '/plugin/products/patch/v1/enforcements'
    uri = "https://" + hostname + api
    body = {
        "modelId": mwID,
        "modelName": 'MaintenanceWindow',
        "taniumGroupId": computergroupID
    }
    jobj = json.dumps(body)
    headers = {
        'Content-Type': 'application/json',
        'session': sessionID
    }
    r = requests.post(uri, verify=False, data=jobj, headers=headers)
    jsonobj = r.json()
    return jsonobj

def main():
    run_module()

if __name__ == '__main__':
    main()