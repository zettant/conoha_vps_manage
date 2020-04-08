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
            '[-t name_tag] [-p admin_password] [--ip name_tag]' \
            '[--start name_tag] [--reboot name_tag] [--shutdown name_tag] [--delete name_tag] ' \
            '[--rule] [--dns domain] [--dns-add domain] [--dns-del domain] [--hostname name] [--address ip_addr] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-i', '--ini', type=str, default="./config.ini", help='config file')
    argparser.add_argument('--create', action='store_true', help='create a new server')
    argparser.add_argument('-s', '--script', type=str, help='file path of startup script')
    argparser.add_argument('-t', '--tag', type=str, help='name tag of the server to create')
    argparser.add_argument('-p', '--password', type=str, help='admin password of the server to create')
    argparser.add_argument('-c', '--check', type=str, help='check conoha parameter list')
    argparser.add_argument('-l', '--list', action='store_true', help='list up conoha servers')
    argparser.add_argument('--dns', type=str, help='dns records of the domain')
    argparser.add_argument('--dns-add', type=str, help='add A record in the DNS')
    argparser.add_argument('--dns-del', type=str, help='delete A record in the DNS')
    argparser.add_argument('--address', type=str, help='IP address of the A record')
    argparser.add_argument('--hostname', type=str, help='hostname of the A record')
    argparser.add_argument('--ip', type=str, help='get IP address of the server')
    argparser.add_argument('--start', type=str, help='start server instance')
    argparser.add_argument('--reboot', type=str, help='reboot server instance')
    argparser.add_argument('--shutdown', type=str, help='shutdown server instance')
    argparser.add_argument('--delete', type=str, help='delete server instance with the tag name')
    argparser.add_argument('--create-rule', action='store_true', help='create a new security group and its rule')
    argparser.add_argument('--security-group-del', type=str, help='delete security group')
    args = argparser.parse_args()
    return args


def read_config(filepath):
    if not os.path.exists(filepath):
        print("Error: No config.ini file found.")
        sys.exit(1)
    config_file = configparser.ConfigParser()
    config_file.read(filepath)
    return config_file["admin"], config_file["server"], config_file["rule"], config_file["api"]


def get_conoha_token(base_url, tid, user, passwd):
    """Function of getting a text of conoha token"""
    _api = base_url +"tokens"
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


def get_flavor_uuid(base_url, tid, token, flavorname):
    """Function of getting Conoha Server Plan ID from Server Plan Name"""
    _api = base_url + tid + '/flavors/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['flavors']:
            if server['name'] == flavorname:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa flavor uuid.', e)
        sys.exit(1)


def show_plan_list(base_url, tid, token):
    """Function of getting Conoha Server Plan list"""
    _api = base_url + tid + '/flavors/detail'
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


def get_image_uuid(base_url, tid, token, imagename):
    """Function of getting Conoha Server Image ID from Server Image Name"""
    _api = base_url + tid + '/images/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['images']:
            if server['name'] == imagename:
                return server['id']
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa image uuid.\n', e)
        sys.exit(1)


def show_image_list(base_url, tid, token):
    """Function of getting Conoha Server Images List"""
    _api = base_url + tid + '/images/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['images']:
            print('{name}:\t{id}'.format(name=server['name'], id=server['id']))
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa Image uuid.\n', e)
        sys.exit(1)


def show_security_group_list(base_url,  token):
    """Function of getting Conoha Server Images List"""
    _api = base_url + 'security-groups'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.get(_api, headers=_header)
        for rule in json.loads(_res.content)['security_groups']:
            pprint.pprint(rule)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa security group settings\n', e)
        sys.exit(1)


def create_server(base_url, tid, sgroup, stag, token, admin_pass, fid, iid, script):
    """Function of creating New Server"""
    _api = base_url + tid + '/servers'
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


def delete_server(base_url, tid, token, server_id):
    """Function of delete Conoha Server"""
    _api = base_url + tid + '/servers/' + server_id
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.delete(_api, headers=_header)
        if _res.status_code != 204:
            print('Error: Could not delete ConoHa server.\n')
            sys.exit(1)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not delete ConoHa server.\n', e)
        sys.exit(1)


def send_server_action(base_url, tid, token, server_id, body):
    """Function of sending action to Conoha Server"""
    _api = base_url + tid + '/servers/' + server_id + "/action"
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.post(_api, data=json.dumps(body), headers=_header)
        print(_res.text)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not send action to server.\n', e)
        sys.exit(1)


def get_server_list(base_url, tid, token):
    """Function of getting ConoHa Server list"""
    _api = base_url + tid + '/servers/detail'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        result = {}
        _res = requests.get(_api, headers=_header)
        for server in json.loads(_res.content)['servers']:
            name = server["metadata"]["instance_name_tag"]
            result[name] = {
                "status": server["status"],
                "id": server["id"]
            }
            for addr in [ "%s"%a["addr"] for a in list(server["addresses"].values())[0] ]:
                if ":" in addr:
                    result[name]["ipv6"] = addr
                else:
                    result[name]["ipv4"] = addr
        return result
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa server list.', e)
        sys.exit(1)


def create_security_group(base_url, token, group_name):
    """Function of creating security group"""
    _api = base_url + 'security-groups'
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


def delete_security_group(base_url, token, group_id):
    """Function of deleting security group"""
    _api = base_url + 'security-groups/' + group_id
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}

    try:
        _res = requests.delete(_api, headers=_header)
        if _res.status_code != 204:
            print("ERROR: ", _res.text)
            sys.exit(1)
        return

    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not create server.', e)
        sys.exit(1)
    except KeyError:
        print('Error Code   : {code}\nError Message: {res}'.format(
            code=_res.text['badRequest']['message'],
            res=_res.text['badRequest']['code']))
        sys.exit(1)


def add_firewall_rule(base_url, token, group_id, port):
    """Function of adding firewall rule in the security group"""
    _api = base_url + 'security-group-rules'
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


def get_domain_list(base_url, token):
    """Function of getting Conoha Domain list"""
    _api = base_url + 'domains'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        result = {}
        _res = requests.get(_api, headers=_header)
        for record in json.loads(_res.content)['domains']:
            result[record["name"]] = record["id"]
        return result
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa domain list.', e)
        sys.exit(1)


def get_dns_records(base_url, token, domain_id):
    """Function of getting Conoha record list"""
    _api = base_url + 'domains/' + domain_id + '/records'
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        result = {}
        _res = requests.get(_api, headers=_header)
        for record in json.loads(_res.content)['records']:
            result[record["id"]] = {
                "name": record["name"],
                "type": record["type"],
                "ip": record["data"]
            }
        return result
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not get ConoHa domain list.', e)
        sys.exit(1)


def add_dns_record(base_url, token, domain_id, name, ip_address, rec_type="A"):
    """Function of adding A record of DNS"""
    _api = base_url + 'domains/' + domain_id + '/records'
    _header = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': token}
    _body = {
        "name": name,
        "type": rec_type,
        "data": ip_address
    }

    try:
        _res = requests.post(_api, data=json.dumps(_body), headers=_header)
        if _res.status_code != 200:
            print("ERROR: ", _res.text)
            sys.exit(1)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not set dns record.', e)
        sys.exit(1)
    except KeyError:
        print('Error Code   : {code}\nError Message: {res}'.format(
            code=_res.text['badRequest']['message'],
            res=_res.text['badRequest']['code']))
        sys.exit(1)


def del_dns_record(base_url, token, domain_id, record_id):
    """Function of deleting A record of DNS"""
    _api = base_url + 'domains/' + domain_id + '/records/' + record_id
    _header = {'Accept': 'application/json', 'X-Auth-Token': token}
    try:
        _res = requests.delete(_api, headers=_header)
        if _res.status_code != 200:
            print("ERROR: ", _res.text)
            sys.exit(1)
    except (ValueError, NameError, ConnectionError, RequestException, HTTPError) as e:
        print('Error: Could not delete dns record.', e)
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


def get_ip(ip_addr):
    for s in get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token):
        if s["name"] == ip_addr:
            return s["ipv4"]
    return None


if __name__ == '__main__':
    arg = _parser()
    admin_conf, server_conf, rule_conf, api_conf = read_config(arg.ini)
    tenant = admin_conf["TENANT"]
    token = get_conoha_token(api_conf["CONOHA_IDENTITY_ENDPOINT_BASE"], tenant, admin_conf["APIUSER"], admin_conf["APIPASS"])

    if arg.check is not None:
        if arg.check == "images":
            show_image_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token)
        elif arg.check == "security_groups":
            show_security_group_list(tenant, token)
        elif arg.check == "plans":
            show_plan_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token)
        sys.exit(0)

    if arg.ip is not None:
        res = get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token).get(arg.ip, None)
        if res is not None:
            print(res["ipv4"])
        else:
            print("***ERROR***")
            sys.exit(1)
        sys.exit(0)

    if arg.list:
        pprint.pprint(get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token))
        sys.exit(0)

    if arg.create_rule:
        sec_id = create_security_group(api_conf["CONOHA_NETWORK_ENDPOINT_BASE"], token, rule_conf["SECURITYGROUP"])
        for port in rule_conf["ALLOW_PORTS"].strip().split(","):
            add_firewall_rule(api_conf["CONOHA_NETWORK_ENDPOINT_BASE"], token, sec_id, port)
        show_security_group_list(api_conf["CONOHA_NETWORK_ENDPOINT_BASE"], tenant, token)
        sys.exit(0)
    elif arg.security_group_del is not None:
        delete_security_group(api_conf["CONOHA_NETWORK_ENDPOINT_BASE"], token, arg.security_group_del)
        sys.exit(0)

    if arg.dns is not None:
        domain_id = get_domain_list(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token).get(arg.dns+".", None)
        if domain_id is None:
            print("No such domain")
            sys.exit(1)
        pprint.pprint(get_dns_records(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id))
        sys.exit(0)
    elif arg.dns_add is not None:
        domain_id = get_domain_list(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token).get(arg.dns_add+".", None)
        if domain_id is None:
            print("No such domain")
            sys.exit(1)
        add_dns_record(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id, arg.hostname+"."+arg.dns_add+".", arg.address)
        pprint.pprint(get_dns_records(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id))
        sys.exit(0)
    elif arg.dns_del is not None:
        domain_id = get_domain_list(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token).get(arg.dns_del+".", None)
        if domain_id is None:
            print("No such domain")
            sys.exit(1)
        for rec_id, rec in get_dns_records(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id).items():
            if rec["name"] != arg.hostname+"."+arg.dns_del+".":
                continue
            del_dns_record(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id, rec_id)
            break
        pprint.pprint(get_dns_records(api_conf["CONOHA_DNS_ENDPOINT_BASE"], token, domain_id))
        sys.exit(0)

    if arg.start is not None:
        svr = get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token).get(arg.start, None)
        if "id" in svr:
            send_server_action(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, svr["id"], {"os-start": "null"})
        sys.exit(0)
    elif arg.reboot is not None:
        svr = get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token).get(arg.reboot, None)
        if "id" in svr:
            send_server_action(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, svr["id"], {"reboot": {"type": "soft"}})
        sys.exit(0)
    elif arg.shutdown is not None:
        svr = get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token).get(arg.shutdown, None)
        if "id" in svr:
            send_server_action(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, svr["id"], {"os-stop": "null"})
        sys.exit(0)
    elif arg.delete is not None:
        svr = get_server_list(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token).get(arg.delete, None)
        if "id" in svr:
            delete_server(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, svr["id"])
        sys.exit(0)

    if not arg.create:
        print("# do nothing. You may need to add --create option")
        sys.exit(0)
    flavor_uuid = get_flavor_uuid(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, server_conf["FLAVORNAME"])
    image_uuid = get_image_uuid(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, token, server_conf["IMAGENAME"])
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
    create_server(api_conf["CONOHA_COMPUTE_ENDPOINT_BASE"], tenant, server_conf["SECGRP"], server_tag, token,
                  server_pass, flavor_uuid, image_uuid, startup_script)