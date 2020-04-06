"""
*  [2020] Zettant Incorporated
*  All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of Zettant Incorporated and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Zettant Incorporated and its
* suppliers and may be covered by Japan. and Foreign Patents,
* patents in process, and are protected by trade secret or
* copyright law. Dissemination of this information or
* reproduction of this material is strictly forbidden unless
* prior written permission is obtained from Zettant Incorporated.
"""

from argparse import ArgumentParser
import configparser
from requests.exceptions import *
import base64
import json
import requests
import sys
import os
import time
import pprint


CONOHA_IDENTITY_ENDPOINT_BASE = "https://identity.tyo1.conoha.io/v2.0/"
CONOHA_COMPUTE_ENDPOINT_BASE = "https://compute.tyo1.conoha.io/v2/"
CONOHA_NETWORK_ENDPOINT_BASE = "https://networking.tyo1.conoha.io/v2.0/"


def _parser():
    usage = 'python {} [-i ini file] [-c] [-f script_file] [-c images|security_groups|plans|] ' \
            '[-t name_tag] [-p amdin_password] ' \
            '[--start server_id] [--reboot server_id] [--shutdown sevrer_id] [--delete sevrer_id] ' \
            '[--rule] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-i', '--ini', type=str, default="./config.ini", help='config file')
    argparser.add_argument('--create', action='store_true', help='create a new server')
    argparser.add_argument('-s', '--script', type=str, help='file path of startup script')
    argparser.add_argument('-t', '--tag', type=str, help='name tag of the server to create')
    argparser.add_argument('-p', '--password', type=str, help='admin password of the server to create')
    argparser.add_argument('-c', '--check', type=str, help='check conoha parameter list')
    argparser.add_argument('-l', '--list', action='store_true', help='list up conoha servers')
    argparser.add_argument('--ip', type=str, help='get IP address of the server')
    argparser.add_argument('--start', type=str, help='start server instance')
    argparser.add_argument('--reboot', type=str, help='reboot server instance')
    argparser.add_argument('--shutdown', type=str, help='shutdown server instance')
    argparser.add_argument('--delete', type=str, help='delete server instance')
    argparser.add_argument('--rule', action='store_true', help='create a new security group and its rule')
    args = argparser.parse_args()
    return args


def read_config(filepath):
    if not os.path.exists(filepath):
        print("Error: No config.ini file found.")
        sys.exit(1)
    config_file = configparser.ConfigParser()
    config_file.read(filepath)
    return config_file["admin"], config_file["server"], config_file["rule"]


def get_conoha_token(tid, user, passwd):
    """Function of getting a text of conoha token"""
    _api = CONOHA_IDENTITY_ENDPOINT_BASE+"tokens"
    _header = {'Accept': 'application/json'}
    _body = {
        "auth": {
            "passwordCredentials": {
                "username": user,
                "password": passwd
            },
            "tenantId": tid
        }}

    try:
        _res = requests.post(_api, data=json.dumps(_body), headers=_header)
        return (json.loads(_res.text))["access"]["token"]["id"]
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa token text.', e)
        sys.exit(1)


def get_flavor_uuid(tid, token, flavorname):
    """Function of getting Conoha Server Plan ID from Server Plan Name"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/flavors/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['flavors']:
            if server['name'] == flavorname:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa flavor uuid.', e)
        sys.exit(1)


def show_plan_list(tid, token):
    """Function of getting Conoha Server Plan list"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/flavors/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.get(_api, headers=_header)
        for flavor in json.loads(_res.content)['flavors']:
            print("{name}:\tcpu:{vcpus}, ram:{ram}, disk:{disk}".format(
                name=flavor["name"],
                vcpus=flavor["vcpus"],
                ram=flavor["ram"],
                disk=flavor["disk"]
            ))
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa flavor uuid.', e)
        sys.exit(1)


def get_image_uuid(tid, token, imagename):
    """Function of getting Conoha Server Image ID from Server Image Name"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/images/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['images']:
            if server['name'] == imagename:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa image uuid.\n', e)
        sys.exit(1)


def show_image_list(tid, token):
    """Function of getting Conoha Server Images List"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/images/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['images']:
            print('{name}:\t{id}'.format(name=server['name'], id=server['id']))
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa Image uuid.\n', e)
        sys.exit(1)


def show_security_group_list(tid, token):
    """Function of getting Conoha Server Images List"""
    _api = CONOHA_NETWORK_ENDPOINT_BASE + 'security-groups'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for rule in json.loads(_res.content)['security_groups']:
            pprint.pprint(rule)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa security group settings\n', e)
        sys.exit(1)


def create_server(tid, sgroup, stag, token, admin_pass, fid, iid, script):
    """Function of creating New Server"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/servers'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    _body = {
        "server": {
            "security_groups": [{"name": sgroup}],
            "metadata": {"instance_name_tag": stag},
            "adminPass": admin_pass,
            "flavorRef": fid,
            "imageRef": iid
        }
    }
    if script != "":
        _body["server"]["user_data"] = script

    try:
        _res = requests.post(_api, data=json.dumps(_body), headers=_header)
        if _res.status_code != 202:
            print("ERROR: ", _res.text)
            sys.exit(1)
        if json.loads(_res.text)['server']:
            print(_res.text)
            print('Success: New server started!')

    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not create server.', e)
        sys.exit(1)
    except KeyError:
        print('Error Code   : {code}\nError Message: {res}'.format(
            code=_res.text['badRequest']['message'],
            res=_res.text['badRequest']['code']))
        sys.exit(1)


def delete_server(tid, token, server_id):
    """Function of delete Conoha Server"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/servers/' + server_id
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.delete(_api, headers=_header)
        if _res.status_code != 204:
            print('Error: Could not delete ConoHa server.\n')
            sys.exit(1)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not delete ConoHa server.\n', e)
        sys.exit(1)


def send_server_action(tid, token, server_id, body):
    """Function of sending action to Conoha Server"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/servers/' + server_id + "/action"
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.post(_api, data=json.dumps(body), headers=_header)
        print(_res.text)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not send action to server.\n', e)
        sys.exit(1)


def get_server_list(tid, token):
    """Function of getting Conoha Server list"""
    _api = CONOHA_COMPUTE_ENDPOINT_BASE + tid + '/servers/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        result = []
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['servers']:
            info = dict()
            info["name"] = server["metadata"]["instance_name_tag"]
            info["status"] = server["status"]
            info["id"] = server["id"]
            for addr in [ "%s"%a["addr"] for a in list(server["addresses"].values())[0] ]:
                if ":" in addr:
                    info["ipv6"] = addr
                else:
                    info["ipv4"] = addr
            result.append(info)
        return result
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa flavor uuid.', e)
        sys.exit(1)


def create_security_group(token, group_name):
    """Function of creating security group"""
    _api = CONOHA_NETWORK_ENDPOINT_BASE + '/security-groups'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    _body = {
        "security_group": {
            "name": group_name,
            "description": group_name
        }
    }

    try:
        _res = requests.post(_api, data=json.dumps(_body), headers=_header)
        if _res.status_code != 201:
            print("ERROR: ", _res.text)
            sys.exit(1)
        return json.loads(_res.content)['security_group']['id']

    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not create server.', e)
        sys.exit(1)
    except KeyError:
        print('Error Code   : {code}\nError Message: {res}'.format(
            code=_res.text['badRequest']['message'],
            res=_res.text['badRequest']['code']))
        sys.exit(1)


def add_firewall_rule(token, group_id, port):
    """Function of adding firewall rule in the security group"""
    _api = CONOHA_NETWORK_ENDPOINT_BASE + '/security-group-rules'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    _body = {
        "security_group_rule": {
            "direction": "ingress",
            "ethertype": "IPv4",
            "security_group_id": group_id,
            "port_range_min": port,
            "port_range_max": port,
            "protocol": "tcp"
        }
    }

    try:
        _res = requests.post(_api, data=json.dumps(_body), headers=_header)
        if _res.status_code != 201:
            print("ERROR: ", _res.text)
            sys.exit(1)

    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not create server.', e)
        sys.exit(1)
    except KeyError:
        print('Error Code   : {code}\nError Message: {res}'.format(
            code=_res.text['badRequest']['message'],
            res=_res.text['badRequest']['code']))
        sys.exit(1)


def get_startup_base64(src_path):
    """Function of transforming from shell script to base64 value"""
    with open(src_path, encoding='utf-8') as f:
        _script_text = f.read()

    try:
        return base64.b64encode(_script_text.encode('utf-8')).decode()
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get base64 value of startup script.\n', e)
        sys.exit(1)


if __name__ == '__main__':
    arg = _parser()
    admin_conf, server_conf, rule_conf = read_config(arg.ini)
    tenant = admin_conf["TENANT"]
    token = get_conoha_token(tenant, admin_conf["APIUSER"], admin_conf["APIPASS"])

    if arg.check is not None:
        if arg.check == "images":
            show_image_list(tenant, token)
        elif arg.check == "security_groups":
            show_security_group_list(tenant, token)
        elif arg.check == "plans":
            show_plan_list(tenant, token)
        sys.exit(0)

    if arg.ip is not None:
        for s in get_server_list(tenant, token):
            if s["name"] == arg.ip:
                print(s["ipv4"])
                break
        sys.exit(0)

    if arg.list:
        pprint.pprint(get_server_list(tenant, token))
        sys.exit(0)

    if arg.rule:
        sec_id = create_security_group(token, rule_conf["SECURITYGROUP"])
        for port in rule_conf["ALLOW_PORTS"].strip().split(","):
            add_firewall_rule(token, sec_id, port)
        show_security_group_list(tenant, token)
        sys.exit(0)

    if arg.start is not None:
        send_server_action(tenant, token, arg.start, {"os-start": "null"})
        sys.exit(0)
    elif arg.reboot is not None:
        send_server_action(tenant, token, arg.reboot, {"reboot": {"type": "soft"}})
        sys.exit(0)
    elif arg.shutdown is not None:
        send_server_action(tenant, token, arg.shutdown, {"os-stop": "null"})
        sys.exit(0)
    elif arg.delete is not None:
        delete_server(tenant, token, arg.delete)
        sys.exit(0)

    if not arg.create:
        print("# do nothing. You may need to add --create option")
        sys.exit(0)
    flavor_uuid = get_flavor_uuid(tenant, token, server_conf["FLAVORNAME"])
    image_uuid = get_image_uuid(tenant, token, server_conf["IMAGENAME"])
    if arg.tag is not None:
        server_tag = arg.tag
    else:
        server_tag = server_conf["STAG"]
    if arg.password is not None:
        server_pass = arg.password
    else:
        server_pass = server_conf["ROOTPASS"]
    if arg.script is None:
        startup_script = ""
    else:
        startup_script = get_startup_base64(arg.script)
    print("** please wait for a while")
    create_server(tenant, server_conf["SECGRP"], server_tag, token,
                  server_pass, flavor_uuid, image_uuid, startup_script)

