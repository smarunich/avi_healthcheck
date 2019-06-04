#!/usr/bin/python
import requests
import re
import json
import argparse
import StringIO
import tarfile
import datetime
import getpass
import requests.packages.urllib3 
requests.packages.urllib3.disable_warnings()
#VMWARE Imports
from pyVim.connect import SmartConnect, SmartConnectNoSSL
from pyVmomi import vim, VmomiSupport
from pyVmomi.VmomiSupport import VmomiJSONEncoder
#K8 and OCP Imports
import kubernetes.client
from kubernetes.client.rest import ApiException
import openshift.client
#used for SSH
import paramiko
#Communication to controller
from avi.sdk.avi_api import ApiSession

from avi.util.ssl_utils import encrypt_string, decrypt_string
import os
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
sys.path.append('/opt/avi/python/bin/portal')
os.environ["DJANGO_SETTINGS_MODULE"] = "portal.settings_full"
#import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1

class Avi(object):
    def __init__(self, host='127.0.0.1', username='admin', password=None, verify=False, output_dir=None, tenant='*', avi_api_version='17.2.14',timeout=300, cloud_name='Default-Cloud'):
        if password == None:
            raise Exception('Avi authentication account password not provided')
        self.export = None
        self.se_connections = []
        self.ctrl_connections = []
        self.node_connections = []
        self.cloud_name = cloud_name
        self.k8s = []
        self.host = host
        self.username = username
        self.password = password
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.base_url = 'https://' + host
        self.avi_api_version = avi_api_version
        self.tenant = tenant
        self.timeout = timeout

        self.api = ApiSession.get_session(controller_ip = self.host, username=self.username, password=self.password, tenant=self.tenant, api_version=self.avi_api_version, timeout=self.timeout)
        self.backup()

        #TODO should be cleaner
        self.cloud = self._get('cloud', params={'include_name': True, 'page_size': '200', 'name': self.cloud_name})
        if not self.cloud['results']:
            print("Cloud: %s Not found" % self.cloud_name)
            exit()

        self.alerts()
        self.events()
        self.vs_inventory()
        self.network_inventory()
        self.cc_list = self.export['Cloud']
        self.check_key_passphrase(self.export, self.password)

        #TODO Needs to be cleaner
        self.se_inventory = self._get('serviceengine-inventory', params={'include_name': True, 'page_size': '200', "refers_to": 'cloud:'+self.cloud['results'][0]['uuid']})

        #TODO If DNS doesn't exist - this will crash script
        # self.dns_metrics()

        #TODO Is cluster runtime required?  /api/cluster has hostname/vm name/ macaddress and IP
        self.cl_list = self._cluster_runtime()

        #TODO forloop with if statement clean up
        for c in self.cc_list:
            if c['vtype'] == 'CLOUD_OSHIFT_K8S':
                self.k8s.append(K8s(k8s_cloud=c, private_key=self.private_key, output_dir=self.output_dir))
                internals = self._get('cloud/' + c['uuid'] + '/internals')
                for se_ip in self._se_local_addresses(cloud_uuid=c['uuid']):
                    if internals['agents'][0]['oshift_k8s']['cfg']['se_deployment_method'] == 'SE_CREATE_SSH':
                        for node in internals['agents'][0]['oshift_k8s']['hosts']:
                            user = self._find_cc_user(cloud=c)
                            self.node_connections.append(K8sNode(node['host_ip'], controllers=self.cl_list, output_dir=self.output_dir, **user))
                    #TODO Does this need to be done for every cloud type?
                    self.se_connections.append(AviSE(se_ip, password=self.password, controllers=self.cl_list, output_dir=self.output_dir))
            elif c['vtype'] == 'CLOUD_VCENTER' and c['vcenter_configuration']['privilege'] == 'WRITE_ACCESS':
                self.vcenter_session = Vmware(c['vcenter_configuration']['vcenter_url'], c['vcenter_configuration']['username'], decrypt_string(c['vcenter_configuration']['password'], self.private_key))
                self.vmware_runtime = ['cluster','vimgrclusterruntime','vimgrsevmruntime','vimgrvcenterruntime']
                fileName, jsondata = self.vcenter_session.gather_cluster_globals()
                self._write(fileName, jsondata)
                self._api_collection(self.vmware_runtime)

#Collection of each controllers statistics
        for c_ip in self.cl_list:
            self.ctrl_connections.append(AviController(c_ip, password=self.password, controllers=self.cl_list,output_dir=self.output_dir))
        self.archive()

    def check_key_passphrase(self, config, passphrase):
        from django.contrib.auth.hashers import PBKDF2PasswordHasher as pbkdf2
        salt = config.get('META',{}).get('salt', None)
        hasher = pbkdf2()
        _, _, _, key = hasher.encode(passphrase, salt, iterations=100000).split('$', 3)
        try:
            decrypt_string(config.get('META',{}).get('test_string'), key)
        except:
            print 'Invalid passphrase'
            sys.exit(1)
        self.private_key = key
        return key

    def dns_metrics(self):
        self._get_dns_vs()
        uuid = self._dns_vs['uuid']
        path = 'analytics/metrics/virtualservice/' + uuid
        metrics = ['dns_client.avg_resp_type_a',
                   'dns_client.avg_resp_type_aaaa',
                   'dns_client.avg_resp_type_ns',
                   'dns_client.avg_resp_type_srv',
                   'dns_client.avg_resp_type_mx',
                   'dns_client.avg_resp_type_other',
                   'dns_client.avg_complete_queries',
                   'dns_client.avg_invalid_queries',
                   'dns_client.avg_domain_lookup_failures',
                   'dns_client.avg_unsupported_queries',
                   'dns_client.avg_gslbpool_member_not_available',
                   'dns_client.avg_tcp_passthrough_errors',
                   'dns_client.avg_udp_passthrough_errors',
                   'dns_client.pct_errored_queries',
                   'dns_client.avg_tcp_queries',
                   'dns_client.avg_udp_queries',
                   'l4_client.avg_bandwidth']
        m = ','.join(metrics)
        params = {'metric_id': m,
                  'aggregation': 'METRICS_ANOMALY_AGG_COUNT',
                  'aggregation_window': '1',
                  'step': '3600',
                  'limit': '168'}
        self._get(path, params=params)

    def _api_collection(self, collection):
        for api_call in collection:
            self._get(api_call, params={'include_name': True, 'page_size': '50', "refers_to": 'cloud:'+self.cloud['results'][0]['uuid']})

#TODO Clean up - Do these go to _api_collection?????
    def vs_inventory(self):
        r = self._get('virtualservice-inventory', params={'include_name': True, 'page_size': '50', "refers_to": 'cloud:'+self.cloud['results'][0]['uuid']})

    def network_inventory(self):
        r = self._get('network-inventory', params={'include_name': True, 'page_size': '50', "refers_to": 'cloud:'+self.cloud['results'][0]['uuid']})

    def alerts(self):
        r = self._get('alert', params={'include_name': True, 'page_size': '200'})

    def events(self):
        r = self._get('analytics/logs/', params={'include_name': True, 'type': '2', 'duration': '604800', 'page_size': '1000' })

    def backup(self):
        r = self._get('configuration/export', params={'full_system': True, 'passphrase': self.password})
        self.export = r

    def _find_cc_user(self, cloud=None):
        user = {}
        if cloud is not None:
            cloudconnectoruser_ref = ''.join(cloud['oshiftk8s_configuration']['ssh_user_ref'].split('/')[-2:])
            uuid = self._get(cloudconnectoruser_ref)['results'][0]['uuid']
            for ccu in self.export['CloudConnectorUser']:
                if ccu['uuid'] == uuid:
                    user['username'] = ccu['name']
                    user['pem'] = decrypt_string(ccu['private_key'], self.private_key)
        return user

    def _get_dns_vs(self):
        ref = self.export['SystemConfiguration'][0]['dns_virtualservice_refs'][0].split('/')[-1]
        self._dns_vs = self._get('virtualservice/' + ref, params={'include_name': True})

    def _cluster_runtime(self):
        ips = []
        cluster = self._get('cluster/runtime')
        for node in cluster['node_states']:
            ips.append(node['mgmt_ip'])
        return ips

    def _se_local_addresses(self, cloud_uuid=None):
        se_list = []
        securechannel = self._get('securechannel')
        for sc in securechannel['results']:
            for se in self.se_inventory['results']:
                if sc['uuid'] == se['uuid'] and cloud_uuid in se['config']['cloud_ref']:
                    se_list.append(sc['local_ip'])
        return se_list

    def _get(self, uri, params=None):
        r = self.api.get(uri, params=params)
        page = 2
        data = r.json()
        print "Collecting", uri + "..."
        while 'next' in r.json().keys():
          params.update({'page': page})
          r = self.api.get(uri, params=params)
          data['results'].append(r.json()['results'])
          page += 1
        #TODO File name contain cloud name for non-global stats (ie: # ofobjects per cloud)
        file_name = re.sub('\W+','-', uri) + '-avi_healthcheck.json'
        print "Writing", file_name + "..."
        self._write(file_name=file_name, data=data)
        return data

    def _write(self, file_name, data):
        try:
            with open(self.output_dir + '/' + file_name, 'w') as fh:
                json.dump(data, fh)
        except Exception as e:
            print e.message

    def archive(self):
        archive_name = self.output_dir + '/' + self.host + '-avi_healthcheck-' + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + '.tar.gz'
        with tarfile.open(archive_name, mode='w:gz') as archive:
            for root, dirs, files in os.walk(self.output_dir):
                for file in files:
                    if 'avi_healthcheck.json' in file:
                        archive.add(os.path.join(root, file))
                        os.remove(os.path.join(root, file))
        os.chmod(archive_name, 0755)

class Vmware(object):
	def __init__(self, vcenter_server, vcenter_user, vcenter_password, vcenter_port='443'):
		self.host = vcenter_server
		self.user = vcenter_user
		self.password = vcenter_password
		self.port = vcenter_port
        #TODO Build Support for SSL and Non-SSL verify
		session = SmartConnectNoSSL(host=self.host,
                            user=self.user,
                            pwd=self.password,
                            port=self.port)
		self.content = session.content

	def get_all_objs(self, content, vimtype):
			self.obj = {}
			self.container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
			for managed_object_ref in self.container.view:
				self.obj.update({managed_object_ref: managed_object_ref.name})
			return self.obj

	def gather_cluster_globals(self):
		self.clusterList = self.get_all_objs(self.content,[vim.ClusterComputeResource])
		clusterInfo ={}
		file_name = self.host + '-clusterconfig' + '-avi_healthcheck.json'  #based on future changes -> can be removed
		for cluster_id in self.clusterList:
			data = json.dumps(cluster_id.configuration, cls=VmomiJSONEncoder)
		 	clusterInfo[cluster_id.name] = json.loads(data)
		return(file_name, clusterInfo)

class SSH_Base(object):
    def __init__(self, port=22, username=None, password=None, pem=None, output_dir=None):
        self.output_dir = output_dir
        if pem is not None:
            self._pem = StringIO.StringIO(pem)
            self._pem = paramiko.RSAKey.from_private_key(self._pem)
        else:
            self._pem = None
        self._ssh = None
        self._cmd_list = []
        self.local_ip = None
        self.local_port = port
        self.username = username
        self.password = password

    def run_commands(self):
        response_list = []
        for cmd in self._cmd_list:
            response_list.append(self._run_cmd(cmd, sudo=True))
        with open(self.output_dir + '/' + self.local_ip + '.ssh-avi_healthcheck.json', 'w') as fh:
            json.dump(response_list, fh)
        return response_list

    def _configure_ssh(self):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.password is not None:
                ssh.connect(self.local_ip,
                            port=self.local_port,
                            username=self.username,
                            password=self.password)
            elif self._pem is not None:
                ssh.connect(self.local_ip,
                            port=self.local_port,
                            username=self.username,
                            pkey=self._pem)
            print "Connected to host: %s" % self.local_ip
        except Exception as e:
            print "Failed to connect to host: %s" % self.local_ip
            print e.message
            ssh = None
        return ssh

    def _run_cmd(self, command, sudo=False):
        cmd = None
        if self._ssh is not None:
            if sudo:
                command = 'sudo ' + command
            # TODO print is just for some feedback
            print command
            cmd = {'command': command}
            sin, sout, serr = self._ssh.exec_command(command, get_pty=True)
            if sudo and self.password is not None:
                sin.write(self.password + '\n')
                sin.flush()
            cmd['response'] = sout.read()
        return cmd

class AviController(SSH_Base):
    def __init__(self, local_ip, port=22, username='admin', password=None, controllers=None, output_dir=None):
        # TODO
        # Port: 5098 when running controller in a container
        super(AviController, self).__init__(port=port, username=username, password=password)
        self.output_dir = output_dir
        self.local_ip = local_ip
        self.controllers = controllers
        self._cmd_list = ['hostname',
                          'ls -ail /opt/avi/log/*',
                          'ps -aux',
                          'top -b -o +%MEM | head -n 22',
                          '/opt/avi/scripts/taskqueue.py -s',
                          # TODO sort out the cc log name from the config
                          # 'grep "pending changes" /opt/avi/log/cc_agent_Default-Cloud.log',
                          'df -h']
        self._ssh = self._configure_ssh()
        self.command_list = self.run_commands()
        for p in self.ping_controllers():
            self.command_list.append(p)
        try:
            self._ssh.close()
        except Exception as e:
            pass

    def ping_controllers(self):
        ctrl_list = []
        for ip in self.controllers:
            if ip is not self.local_ip:
                ctrl_list.append(self._run_cmd('ping -c5 %s' % ip))
        with open(self.output_dir + '/' +self.local_ip + '.ping-avi_healthcheck.json', 'w') as fh:
            json.dump(ctrl_list, fh)
        return ctrl_list


class AviSE(SSH_Base):
    def __init__(self, local_ip, port=5097, username='admin', password=None, controllers=None, output_dir=None):
        super(AviSE, self).__init__(port=port, username=username, password=password)
        self.output_dir = output_dir
        self.local_ip = local_ip
        self.controllers = controllers
        self._cmd_list = ['hostname',
                          'docker info',
                          'iptables -nvL',
                          'iptables -nvL -t nat',
                          'ip route show table all',
                          'ifconfig',
                          'ip link',
                          'ip addr',
                          'sysctl -a',
                          'df -h',
                          'ls -ail /opt/avi/log',
                          'date',
                          'ntpq -p']
        self._ssh = self._configure_ssh()
        self.command_list = self.run_commands()
        for p in self.ping_controllers():
            self.command_list.append(p)
        try:
            self._ssh.close()
        except Exception as e:
            pass

    def ping_controllers(self):
        ctrl_list = []
        for ip in self.controllers:
            ctrl_list.append(self._run_cmd('ping -c5 %s' % ip))
        with open(self.output_dir + '/' + self.local_ip + '.ping-avi_healthcheck.json', 'w') as fh:
            json.dump(ctrl_list, fh)
        return ctrl_list


class K8sNode(SSH_Base):
    def __init__(self, local_ip, port=22, username=None, password=None, pem=None, controllers=None, output_dir=None):
        super(K8sNode, self).__init__(port=port, username=username, password=password, pem=pem, output_dir=output_dir)
        self.output_dir = output_dir
        self.local_ip = local_ip
        self.controllers = controllers
        self._cmd_list = ['hostname',
                          'docker info',
                          'iptables -nvL',
                          'iptables -nvL -t nat',
                          'ip route show table all',
                          'ifconfig',
                          'ip link',
                          'ip addr',
                          'sysctl -a',
                          'df -h',
                          'date',
                          'ntpq -p']
        self._ssh = self._configure_ssh()
        self.command_list = self.run_commands()
        for p in self.ping_controllers():
            self.command_list.append(p)
        try:
            self._ssh.close()
        except Exception as e:
            pass

    def ping_controllers(self):
        ctrl_list = []
        for ip in self.controllers:
            ctrl_list.append(self._run_cmd('ping -c5 %s' % ip))
        with open(self.output_dir + '/' + self.local_ip + '.ping-avi_healthcheck.json', 'w') as fh:
            json.dump(ctrl_list, fh)
        return ctrl_list


class K8s(object):
    def __init__(self, k8s_cloud=None, private_key=None, output_dir=None):
        self.output_dir = output_dir
        if 'str' and 'iv' in k8s_cloud['oshiftk8s_configuration']['service_account_token']:
            authorization_token = decrypt_string(k8s_cloud['oshiftk8s_configuration']['service_account_token'], private_key)
        else:
            authorization_token = k8s_cloud['oshiftk8s_configuration']['service_account_token']
        self._kauth = kubernetes.client.Configuration()
        if 'https://' not in k8s_cloud['oshiftk8s_configuration']['master_nodes'][0]:
            host_url = 'https://' + k8s_cloud['oshiftk8s_configuration']['master_nodes'][0]
        else:
            host_url = k8s_cloud['oshiftk8s_configuration']['master_nodes'][0]
        self._kauth.host = host_url
        self._kauth.verify_ssl = False
        self._kauth.api_key['authorization'] = authorization_token
        self._kauth.api_key_prefix['authorization'] = 'Bearer'

        self._oauth = kubernetes.client.Configuration()
        self._oauth.host = host_url
        self._oauth.verify_ssl = False
        self._oauth.api_key['authorization'] = authorization_token
        self._oauth.api_key_prefix['authorization'] = 'Bearer'

        self.v1Api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(self._kauth))
        self.nodes = self._k8s_api(self.v1Api, 'list_node')
        self.services = self._k8s_api(self.v1Api, 'list_service_for_all_namespaces')
        self.serviceaccounts = self._k8s_api(self.v1Api, 'list_service_account_for_all_namespaces')

        self.oapi = openshift.client.OapiApi(openshift.client.ApiClient(self._oauth))
        self.projects = self._k8s_api(self.oapi, 'list_project')

    def _k8s_api(self, api, cmd):
        try:
            print api, cmd
            response = getattr(api, cmd)()
            flat = kubernetes.client.ApiClient().sanitize_for_serialization(response)
            with open(self.output_dir + '/' + 'k8s-' + cmd + '-avi_healthcheck.json', 'w') as fh:
                json.dump(flat, fh)
            return response
        except ApiException as e:
            print 'K8s exception with %s' % cmd
            print e

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', type=str, default=None)
    parser.add_argument('--username', type=str, default='admin')
    parser.add_argument('--password', type=str, default=None)
    parser.add_argument('--cloud_name', type=str, default=None)
    parser.add_argument('--output_dir', type=str, default='.', help='Output directory')
    parser.add_argument('--api-version', type=str, default='17.2.14', help='X-Avi-Version' )
    parser.add_argument('--tenant', type=str, default='*', help='X-Avi-Tenant')
    parser.add_argument('--timeout', type=float, default=300, help='REST API timeout')
    parser.add_argument('--secure_channel_port', type=int, default=5097)
    args = parser.parse_args()

    if args.controller and args.cloud_name:
        avi = Avi(host=args.controller, username=args.username, password=args.password,
          output_dir=args.output_dir, tenant=args.tenant, avi_api_version=args.api_version, timeout=args.timeout, cloud_name=args.cloud_name)
    else:
        host = raw_input("Controller IP: ")
        username = raw_input("Username: ")
        password = getpass.getpass('Password: ')
        output_dir = raw_input("Output Directory: ")
        avi_api_version = raw_input("Avi Vantage version: ")
        cloud_name = raw_input("Cloud Name: ")
        avi = Avi(host=host, username=username, password=password, output_dir=output_dir, avi_api_version=avi_api_version, cloud_name=cloud_name)
