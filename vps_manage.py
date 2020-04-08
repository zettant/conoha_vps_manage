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


def _parser():
    usage = 'python {} [-i ini file] [-c] [-f script_file] [-c images|security_groups|plans|] ' \
            '[-t name_tag] [-p admin_password] ' \
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


def get_conoha_token(api, tid, user, passwd):
    """Function of getting a text of conoha token"""
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
        _res = requests.post(api, data=json.dumps(_body), headers=_header)
        return (json.loads(_res.text))["access"]["token"]["id"]
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa token text.', e)
        sys.exit(1)


def get_flavor_uuid(api, token, flavorname):
    """Function of getting Conoha Server Plan ID from Server Plan Name"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.get(api, headers=_header)
        for server in json.loads(_res.content)['flavors']:
            if server['name'] == flavorname:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa flavor uuid.', e)
        sys.exit(1)


def show_plan_list(api, token):
    """Function of getting Conoha Server Plan list"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.get(api, headers=_header)
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


def get_image_uuid(api, token, imagename):
    """Function of getting Conoha Server Image ID from Server Image Name"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(api, headers=_header)
        for server in json.loads(_res.content)['images']:
            if server['name'] == imagename:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa image uuid.\n', e)
        sys.exit(1)


def show_image_list(api, tid, token):
    """Function of getting Conoha Server Images List"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(api, headers=_header)
        for server in json.loads(_res.content)['images']:
            print('{name}:\t{id}'.format(name=server['name'], id=server['id']))
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa Image uuid.\n', e)
        sys.exit(1)


def show_security_group_list(api, token):
    """Function of getting Conoha Server Images List"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(api, headers=_header)
        for rule in json.loads(_res.content)['security_groups']:
            pprint.pprint(rule)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa security group settings\n', e)
        sys.exit(1)


def create_server(api, sgroup, stag, token, admin_pass, fid, iid, script):
    """Function of creating New Server"""
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
        _res = requests.post(api, data=json.dumps(_body), headers=_header)
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


def delete_server(api, token):
    """Function of delete Conoha Server"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.delete(api, headers=_header)
        if _res.status_code != 204:
            print('Error: Could not delete ConoHa server.\n')
            sys.exit(1)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not delete ConoHa server.\n', e)
        sys.exit(1)


def send_server_action(api, token, body):
    """Function of sending action to Conoha Server"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.post(api, data=json.dumps(body), headers=_header)
        print(_res.text)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not send action to server.\n', e)
        sys.exit(1)


def get_server_list(api, token):
    """Function of getting Conoha Server list"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        result = []
        _res = requests.get(api, headers=_header)
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


def create_security_group(api, token, group_name):
    """Function of creating security group"""
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    _body = {
        "security_group": {
            "name": group_name,
            "description": group_name
        }
    }

    try:
        _res = requests.post(api, data=json.dumps(_body), headers=_header)
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


def add_firewall_rule(api, token, group_id, port):
    """Function of adding firewall rule in the security group"""
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
        _res = requests.post(api, data=json.dumps(_body), headers=_header)
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


def get_api_list(api_conf, tenant, server_id):
    api_list = {
        'tokens': api_conf['CONOHA_IDENTITY_ENDPOINT_BASE']+'tokens',
        'flavors_details': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/flavors/detail',
        'image_details': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/images/detail',
        'flavors_detail': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/flavors/detail',
        'servers_detail': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/servers/detail',
        'server_action': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/servers/' + server_id + '/action',
        'server_delete': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/servers/' + server_id,
        'images_detail': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/images/detail',
        'server_create': api_conf['CONOHA_COMPUTE_ENDPOINT_BASE'] + tenant + '/servers',
        'security-group-rules': api_conf['CONOHA_NETWORK_ENDPOINT_BASE'] + 'security-group-rules',
        'security-groups': api_conf['CONOHA_NETWORK_ENDPOINT_BASE'] + 'security-groups'
    }
    return api_list


if __name__ == '__main__':
    arg = _parser()
    admin_conf, server_conf, rule_conf, api_conf = read_config(arg.ini)
    tenant = admin_conf['TENANT']

    server_id = ''
    if arg.start is not None:
        server_id = arg.start
    elif arg.reboot is not None:
        server_id = arg.reboot
    elif arg.shutdown is not None:
        server_id = arg.shutdown
    elif arg.delete is not None:
        server_id = arg.delete

    api_list = get_api_list(api_conf, tenant, server_id)
    token = get_conoha_token(api_list['tokens'], tenant, admin_conf['APIUSER'], admin_conf['APIPASS'])

    if arg.check is not None:
        if arg.check == 'images':
            show_image_list(api_list['images_detail'], token)
        elif arg.check == 'security_groups':
            show_security_group_list(api_list['security-groups'], token)
        elif arg.check == 'plans':
            show_plan_list(api_list['flavors_detail'], token)
        sys.exit(0)

    if arg.ip is not None:
        for s in get_server_list(api_list['servers_detail'], token):
            if s['name'] == arg.ip:
                print(s['ipv4'])
                break
        sys.exit(0)

    if arg.list:
        pprint.pprint(get_server_list(api_list['servers_detail'], token))
        sys.exit(0)

    if arg.rule:
        sec_id = create_security_group(api_list['security-groups'], token, rule_conf['SECURITYGROUP'])
        for port in rule_conf['ALLOW_PORTS'].strip().split(','):
            add_firewall_rule(api_list['security-group-rules'], token, sec_id, port)
        show_security_group_list(api_list['security-groups'], token)
        sys.exit(0)

    if arg.start is not None:
        send_server_action(api_list['server_action'], tenant, token, {'os-start': 'null'})
        sys.exit(0)
    elif arg.reboot is not None:
        send_server_action(api_list['server_action'], tenant, token, {'reboot': {'type': 'soft'}})
        sys.exit(0)
    elif arg.shutdown is not None:
        send_server_action(api_list['server_action'], tenant, token, {'os-stop': 'null'})
        sys.exit(0)
    elif arg.delete is not None:
        delete_server(api_list['server_delete'], token)
        sys.exit(0)

    if not arg.create:
        print('# do nothing. You may need to add --create option')
        sys.exit(0)

    flavor_uuid = get_flavor_uuid(api_list['flavors_details'], token, server_conf['FLAVORNAME'])
    image_uuid = get_image_uuid(api_list['images_detail'], token, server_conf['IMAGENAME'])
    if arg.tag is not None:
        server_tag = arg.tag
    else:
        server_tag = server_conf['STAG']
    if arg.password is not None:
        server_pass = arg.password
    else:
        server_pass = server_conf['ROOTPASS']
    if arg.script is None:
        startup_script = ''
    else:
        startup_script = get_startup_base64(arg.script)
    print('** please wait for a while')
    create_server(api_list['server_create'], server_conf['SECGRP'], server_tag, token,
                  server_pass, flavor_uuid, image_uuid, startup_script)

