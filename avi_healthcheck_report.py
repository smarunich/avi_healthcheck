#!/usr/bin/python
import json
import re
import argparse
import datetime
import pandas as pd
from collections import OrderedDict
from pandas.io.json import json_normalize

class K8s():
    def __init__(self, file_path):
        with open(file_path + '/k8s-list_project-avi_healthcheck.json') as file_name:
            self.k8s_projects = json.load(file_name)
        #with open(file_path + '*.ssh-avi_healthcheck.json') as file_name:
        #    self.ssh_commands = json.load(file_name)
        #print self.ssh_commands
    def projects_list(self):
        projects_list = []
        for project in self.k8s_projects['items']:
            projects_list.append(project['metadata']['name'])
        return projects_list

class VMWare():
    def __init__(self, file_path, vcenter_ip):
        with open(file_path + '/'+vcenter_ip+'-clusterconfig-avi_healthcheck.json') as file_name:
            self.vcenter_cluster_globals = json.load(file_name)
    
    def drs_search(self, cluster_name, search_filter):
        for drsVMConfig in self.vcenter_cluster_globals[cluster_name]['drsVmConfig']:
            if re.search(search_filter, drsVMConfig['key']):
                return(drsVMConfig['behavior'])
        return('Uses defaultVmBehavior')

    def antiaffinity_search(self, cluster_name, search_filter):
        for rule in self.vcenter_cluster_globals[cluster_name]['rule']:
            for vm in rule['vm']:
                if re.search(search_filter, vm):
                    return(rule['name'], rule['_vimtype'])
        return('Not Configured', 'Defaults Used')

#search inside configuration by navigating nested objects(args)
    def search(self, *argv):
        configuration = self.vcenter_cluster_globals
        for arg in argv:
            configuration = configuration[arg]
        return(configuration)

class Avi(object):
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path + '/cloud-avi_healthcheck.json') as file_name:
            self.cloud = json.load(file_name)['results'][0]
        with open(file_path + '/configuration-export-avi_healthcheck.json') as file_name:
            self.config = json.load(file_name)
        with open(file_path + '/serviceengine-inventory-avi_healthcheck.json') as file_name:
            self.se_inventory= json.load(file_name)
        with open(file_path + '/cluster-runtime-avi_healthcheck.json') as file_name:
            self.cluster_runtime = json.load(file_name)
        with open(file_path + '/alert-avi_healthcheck.json') as file_name:
            self.alerts = json.load(file_name)['results']
        report = OrderedDict()
        report.update({'total_objs': self.total_objs()})
        report.update({'se_groups': self.se_groups()})
        report.update({'se_vs_distribution': self.se_vs_distribution()})
        #TODO dns_vs_state doesn't always exist
        # report.update({'dns_vs_state': self.dns_vs_state()})
        report.update({'cluster_state': self.cluster_state()})
        report.update({'backup_to_remote_host': self.backup_to_remote_host()})
        #JDA
        report.update({'backup_enabled': self.backup_enabled()})
        report.update({'tenant_count': self.tenant_count()})
        report.update({'default_ntp': self.default_ntp()})
        report.update({'app_profile': self.app_profile()})
        report.update({'net_profile': self.net_profile()})
        report.update({'policies_datascript_info': self.policies_datascript_info()})
        report.update({'vs_analytics': self.vs_analytics()})
        report.update({'analytics_profile': self.analytics_profile()})
        #
        report.update({'alerts': self.alerts})

        if self.cloud['vtype'] == 'CLOUD_OSHIFT_K8S':
            report.update({'cloud': self.cloud_oshiftk8s()})
            report.update({'lingering_tenants': self.find_lingering_tenants()})
        elif self.cloud['vtype'] == 'CLOUD_VCENTER':
            report.update({'cloud': self.cloud_vmware()})

        report_name = 'avi_healthcheck_report_' + self.cloud['name'] + '_' + \
            datetime.datetime.now().strftime("%Y%m%d-%H%M%S" + ".xlsx")
        self.write_report(report_name, report)
    ''' lookup name from obj ref '''
    def _lookup_name_from_obj_ref(self,obj_ref):
        obj_name = re.search(r"name=([^&]*)",
            obj_ref).group(1)
        return obj_name
    ''' total objs for provided cloud '''
    def total_objs(self):
        total_objs = OrderedDict()
        total_objs['VsVip_EW'] = 0
        total_objs['VsVip_NS'] = 0
        for obj_type in self.config.keys():
            total_objs[obj_type] = 0
            for obj in self.config[obj_type]:
                try:
                    if re.search(self.cloud['name'], obj['cloud_ref']):
                        total_objs[obj_type] += 1
                        if obj_type == 'VsVip':
                            if obj['east_west_placement']:
                                total_objs['VsVip_EW'] += 1
                            else:
                                total_objs['VsVip_NS'] += 1
                except:
                    pass
            if total_objs[obj_type] == 0:
                total_objs.pop(obj_type)
        return total_objs

    def cloud_vmware(self):
        vmware_configuration = OrderedDict()
        with open(self.file_path + '/cluster-avi_healthcheck.json') as file_name:
            cluster = json.load(file_name)
        with open(self.file_path + '/vimgrvcenterruntime-avi_healthcheck.json') as file_name:
            vcenter_runtime = json.load(file_name)['results'][0]
        with open(self.file_path + '/vimgrclusterruntime-avi_healthcheck.json') as file_name:
            vcenter_cluster_runtime = json.load(file_name)['results']
        with open(self.file_path + '/vimgrsevmruntime-avi_healthcheck.json') as file_name:
            vcenter_sevm_runtime = json.load(file_name)['results']
        #TODO Re-Use self.cloud??
        for cloud_obj in self.config['Cloud']:
            if re.search(self.cloud['name'], cloud_obj['name']):
                vmware_configuration = {
                    'vcenter_url':
                        cloud_obj['vcenter_configuration']['vcenter_url'],
                    'privilege':
                        cloud_obj['vcenter_configuration']['privilege'],
                     #TODO some type of regex for pg-xxx   
                     #TODO Cloud get doesn't include_name
                     #re.search(r'(?<=#).*',cloud_obj['vcenter_configuration']['management_network']).group()
                    'management_nw': 
                        cloud_obj['vcenter_configuration']['management_network'],
                    'dhcp_enabled':
                        cloud_obj['dhcp_enabled'],
                    'prefer_static_routes':
                        cloud_obj['prefer_static_routes'],
                    'vcenter_version':
                        vcenter_runtime['vcenter_fullname'],
                    'discovered_datacenter':
                        vcenter_runtime['discovered_datacenter']
                }
        vcenter_cluster_config = VMWare(self.file_path, self.cloud['vcenter_configuration']['vcenter_url'])
        
        for sevm in vcenter_sevm_runtime:
            vmware_configuration[sevm['name']+'_object_id'] = \
                sevm['managed_object_id']
            vmware_configuration[sevm['name']+'_connection_state'] = \
                sevm['connection_state']
            vmware_configuration[sevm['name']+'_host_placement'] = \
                sevm['host_ref']
            for cluster_run in vcenter_cluster_runtime:
                for host in cluster_run['host_refs']:
                    if host == sevm['host_ref']:
                        vmware_configuration[cluster_run['name']+'_defaultVmBehavior'] = vcenter_cluster_config.search(cluster_run['name'], "drsConfig", "defaultVmBehavior")
                        vmware_configuration[sevm['name']+'_cluster'] = \
                            cluster_run['name']
                        vmware_configuration[sevm['name']+'_drs_setting'] = \
                            vcenter_cluster_config.drs_search(cluster_run['name'], sevm['managed_object_id'])
                        rule_name, rule_type = vcenter_cluster_config.antiaffinity_search(cluster_run['name'], sevm['managed_object_id'])
                        vmware_configuration[sevm['name']+'_antiaffinity_name'] = rule_name
                        vmware_configuration[sevm['name']+'_antiaffinity_setting'] = rule_type

        for cluster_node in cluster['nodes']:
            if re.search('^vm-\d+',cluster_node['vm_mor']):
                for vm_runtime in self.config['VIMgrVMRuntime']:
                    if vm_runtime['managed_object_id'] == cluster_node['vm_mor']:
                        vmware_configuration[vm_runtime['name']  +'_num_cpu'] = vm_runtime['num_cpu']
                        vmware_configuration[vm_runtime['name']  +'_memory'] = vm_runtime['memory']
                        vmware_configuration[vm_runtime['name']  +'_host_placement'] = vm_runtime['host']
                        for cluster_run in self.config['VIMgrClusterRuntime']:
                            for host in cluster_run['host_refs']:
                                if re.search(vm_runtime['host'], host):
                                    vmware_configuration[vm_runtime['name']+'_drs_setting'] = \
                                    vcenter_cluster_config.drs_search(cluster_run['name'], vm_runtime['managed_object_id'])
                                    rule_name, rule_type = vcenter_cluster_config.antiaffinity_search(cluster_run['name'], vm_runtime['managed_object_id'])
                                    vmware_configuration[vm_runtime['name']+'_antiaffinity_name'] = rule_name
                                    vmware_configuration[vm_runtime['name']+'_antiaffinity_setting'] = rule_type                                   
        return vmware_configuration

    ''' ['Cloud']['oshiftk8s_configuration'] '''
    def cloud_oshiftk8s(self):
        self.k8s = K8s(file_path=self.file_path)
        oshiftk8s_configuration = OrderedDict()
        for cloud_obj in self.config['Cloud']:
             #TODO Future clean up - self.cloud contains cloud configuration, might not need to extract from config file
            if re.search(self.cloud['name'], cloud_obj['name']):
                oshiftk8s_configuration = {
                    'se_deployment_method':
                        cloud_obj['oshiftk8s_configuration']['se_deployment_method'],
                    'use_service_cluster_ip_as_ew_vip':
                        cloud_obj['oshiftk8s_configuration']['use_service_cluster_ip_as_ew_vip'],
                    'default_service_as_east_west_service':
                        cloud_obj['oshiftk8s_configuration']['default_service_as_east_west_service'],
                    'app_sync_frequency':
                        cloud_obj['oshiftk8s_configuration']['app_sync_frequency'],
                    'use_controller_image':
                        cloud_obj['oshiftk8s_configuration']['use_controller_image'],
                    'docker_registry_se':
                        cloud_obj['oshiftk8s_configuration']['docker_registry_se'],
                    'shared_virtualservice_namespace':
                        cloud_obj['oshiftk8s_configuration']['shared_virtualservice_namespace']
                    }
                try:
                    oshiftk8s_configuration['se_include_attributes'] = \
                        cloud_obj['oshiftk8s_configuration']['se_include_attributes']
                except:
                    pass
                try:
                    oshiftk8s_configuration['se_exclude_attributes'] = \
                        cloud_obj['oshiftk8s_configuration']['se_exclude_attributes']
                except:
                    pass
                try:
                    ew_ipam_provider_name = self._lookup_name_from_obj_ref(
                      cloud_obj['east_west_ipam_provider_ref'])
                    oshiftk8s_configuration['ew_configured_subnets'] = []
                    ew_dns_provider_name = self._lookup_name_from_obj_ref(
                      cloud_obj['east_west_dns_provider_ref'])
                except:
                  pass
                ns_ipam_provider_name = self._lookup_name_from_obj_ref(
                    cloud_obj['ipam_provider_ref'])
                oshiftk8s_configuration['nw_configured_subnets'] = []
                ns_dns_provider_name = self._lookup_name_from_obj_ref(
                    cloud_obj['dns_provider_ref'])
                # needs https://10.57.0.40/api/network-inventory for stats
                for provider_obj in self.config['IpamDnsProviderProfile']:
                    try:
                      if ew_ipam_provider_name == provider_obj['name']:
                          for network in provider_obj['internal_profile']['usable_network_refs']:
                              network_uuid = network.split('/')[3]
                              for network_obj in self.config['Network']:
                                  if network_uuid == network_obj['uuid']:
                                      oshiftk8s_configuration['ew_configured_subnets'].append(network_obj['configured_subnets'])
                    except:
                      pass
                    if ns_ipam_provider_name == provider_obj['name']:
                        if 'internal_profile' in provider_obj.keys():
                            for network in provider_obj['internal_profile']['usable_network_refs']:
                                network_uuid = network.split('/')[3]
                                for network_obj in self.config['Network']:
                                    if network_uuid == network_obj['uuid']:
                                        oshiftk8s_configuration['nw_configured_subnets'].append(network_obj['configured_subnets'])
                            if ew_dns_provider_name == provider_obj['name']:
                                oshiftk8s_configuration['ew_configured_domain'] = \
                            provider_obj['internal_profile']['dns_service_domain'][0]['domain_name']
                            if ns_dns_provider_name == provider_obj['name']:
                                oshiftk8s_configuration['ns_configured_domain'] = \
                            provider_obj['internal_profile']['dns_service_domain'][0]['domain_name']
        return oshiftk8s_configuration
    ''' se_groups configuration '''
    def se_groups(self):
        se_groups_configuration = OrderedDict()
        for se_group_obj in self.config['ServiceEngineGroup']:
            if re.search(self.cloud['name'], se_group_obj['cloud_ref']):
                se_groups_configuration[se_group_obj['name']] = {
                    'memory_per_se':
                        se_group_obj['memory_per_se'],
                    'vcpus_per_se':
                        se_group_obj['vcpus_per_se'],
                    'max_vs_per_se':
                        se_group_obj['max_vs_per_se'],
                    'max_se':
                        se_group_obj['max_se'],
                    'min_scaleout_per_vs':
                        se_group_obj['min_scaleout_per_vs'],
                    #JDA
                    'max_scaleout_per_vs':
                        se_group_obj['max_scaleout_per_vs'],    
                    'algo':
                        se_group_obj['algo'],
                    'placement_mode':
                        se_group_obj['placement_mode'],
                    'connection_memory_percentage':
                        se_group_obj['connection_memory_percentage'],
                    'extra_config_multiplier':
                        se_group_obj['extra_config_multiplier'],
                    'extra_shared_config_memory':
                        se_group_obj['extra_shared_config_memory'],
                    'log_disksz':
                        se_group_obj['log_disksz'],
                    }
                try:
                    se_groups_configuration[se_group_obj['name']]['host_attribute_key'] = \
                            se_group_obj['host_attribute_key']
                    se_groups_configuration[se_group_obj['name']]['host_attribute_value'] = \
                            se_group_obj['host_attribute_value']
                except:
                    pass
                try:
                    se_groups_configuration[se_group_obj['name']]['realtime_se_metrics'] = \
                            se_group_obj['realtime_se_metrics']
                except:
                    pass
                try:
                    se_groups_configuration[se_group_obj['name']]['vcenter_datastores_include'] = \
                            se_group_obj['vcenter_datastores_include']
                    se_groups_configuration[se_group_obj['name']]['vcenter_folder'] = \
                            se_group_obj['vcenter_folder']
                    se_groups_configuration[se_group_obj['name']]['vcenter_datastore_mode'] = \
                            se_group_obj['vcenter_datastore_mode']
                    se_groups_configuration[se_group_obj['name']]['vcenter_folder'] = \
                            se_group_obj['vcenter_folder']
                except:
                    pass
        return se_groups_configuration
    ''' se inventory analysis '''
    def se_vs_distribution(self):
        se_vs_distribution = OrderedDict()
        for se in self.se_inventory['results']:
            if re.search(self.cloud['name'], se['config']['cloud_ref']):
                se_vs_distribution[se['config']['name']] = {
                    'nw_vs': len(se['config']['virtualservice_refs']),
                }
        return se_vs_distribution
    ''' cluster runtime analysis '''
    def cluster_state(self):
        cluster_state = self.cluster_runtime['cluster_state']
        return cluster_state
    ''' backup '''
    def backup_to_remote_host(self):
        # Needs https://10.57.0.46/api/backup
        try:
            backup_to_remote_host = self.config['BackupConfiguration']['upload_to_remote_host']
        except:
            backup_to_remote_host = False
        return backup_to_remote_host
    def backup_enabled(self):
        try:
            backup_enabled = False
            for row in self.config['Scheduler']:
                if row['scheduler_action'] == 'SCHEDULER_ACTION_BACKUP':
                    if row['enabled'] == True:
                        backup_enabled = True
                        break
        except:
            backup_enabled = False
        return backup_enabled
    def tenant_count(self):
        try:
            tenant_count = len(self.config['Tenant'])
        except:
            tenant_count = 0
        return tenant_count
    def default_ntp(self):
        try:
            if self.config['SystemConfiguration'][0]['ntp_configuration'].get('ntp_servers'):
                default_ntp = False
            else:
                default_ntp = True
        except:
            default_ntp = False
        return default_ntp
    def app_profile(self):
        app_profile = OrderedDict()
        app_profile['total'] = len(self.config['ApplicationProfile'])
        #HTTP profiles info
        no_mux_http = 0
        http_to_https = 0
        total_http = 0
        try:
            for row in self.config['ApplicationProfile']:
                if row['type'] == 'APPLICATION_PROFILE_TYPE_HTTP':
                    total_http += 1
                    if not row['http_profile']['connection_multiplexing_enabled']:
                        no_mux_http += 1
                    if row['http_profile']['http_to_https']:
                        http_to_https += 1
            app_profile['total_http'] = total_http
            app_profile['no_mux_http'] = no_mux_http
            app_profile['http_to_https'] = http_to_https
        except:
            app_profile['no_mux_http'] = 0
            app_profile['no_mux_http'] = 0
            app_profile['http_to_https'] = 0
        #Preserve client IP
        try:
            preserve_client_ip = 0
            for row in self.config['ApplicationProfile']:
                if row['preserve_client_ip']:
                    preserve_client_ip += 1
            app_profile['preserve_client_ip'] = preserve_client_ip
        except:
            app_profile['preserve_client_ip'] = 0
        
        return app_profile
    def net_profile(self):
        net_profile = OrderedDict()
        net_profile['total'] = len(self.config['NetworkProfile'])
        #TCP-Proxy with manual config params
        try:
            tcpproxy_manual = 0
            tcpproxy_nagles = 0
            for row in self.config['NetworkProfile']:
                if row['profile']['type'] == 'PROTOCOL_TYPE_TCP_PROXY':
                    if not row['profile']['tcp_proxy_profile']['automatic'] :
                        tcpproxy_manual += 1
                        if row['profile']['tcp_proxy_profile']['nagles_algorithm']:
                            tcpproxy_nagles += 1
            net_profile['tcpproxy_manual'] = tcpproxy_manual
            net_profile['tcpproxy_nagles'] = tcpproxy_nagles
        except:
            net_profile['tcpproxy_manual'] = 0
            net_profile['tcpproxy_nagles'] = 0
        #TCP-FastPath with DSR
        try:
            tcpfast_dsr = 0
            for row in self.config['NetworkProfile']:
                if row['profile']['type'] == 'PROTOCOL_TYPE_TCP_FAST_PATH':
                    if row['profile']['tcp_fast_path_profile'].get('dsr_profile'):
                        tcpfast_dsr += 1
            net_profile['tcpfast_dsr'] = tcpfast_dsr
        except:
            net_profile['tcpfast_dsr'] = 0
        
        
        return net_profile
    def policies_datascript_info(self):
        policies_datascript_info = OrderedDict()
        ds_refs = 0
        l4_refs = 0
        try:
            for row in self.config['VirtualService']:
                if re.search(self.cloud['name'], row['cloud_ref']):
                    if row.get('vs_datascripts'):
                        ds_refs += 1
                    if row.get('l4_policies'):
                        l4_refs += 1
            policies_datascript_info['ds_refs'] = ds_refs
            policies_datascript_info['l4_refs'] = l4_refs
        except:
            policies_datascript_info['ds_refs'] = 0
            policies_datascript_info['l4_refs'] = 0
        return policies_datascript_info
    def vs_analytics(self):
        vs_analytics = OrderedDict()
        non_significant = 0
        all_headers = 0
        realtime_metrics = 0
        client_insights = 0
        try:
            for row in self.config['VirtualService']:
                if re.search(self.cloud['name'], row['cloud_ref']):
                    if row['analytics_policy']['full_client_logs']['enabled'] and row['analytics_policy']['full_client_logs']['duration'] == 0:
                        non_significant += 1
                    if row['analytics_policy']['all_headers']:
                        all_headers += 1
                    if row['analytics_policy']['metrics_realtime_update']['enabled'] and row['analytics_policy']['metrics_realtime_update']['duration'] == 0:
                        realtime_metrics += 1
                    if row['analytics_policy']['client_insights'] != 'NO_INSIGHTS':
                        client_insights += 1
            vs_analytics['non_significant'] = non_significant
            vs_analytics['all_headers'] = all_headers
            vs_analytics['realtime_metrics'] = realtime_metrics
            vs_analytics['client_insights'] = client_insights
        except:
            vs_analytics['non_significant'] = 0
            vs_analytics['all_headers'] = 0
            vs_analytics['realtime_metrics'] = 0
            vs_analytics['client_insights'] = 0        
        return vs_analytics
    def analytics_profile(self):
        analytics_profile = OrderedDict()
        stream_logs = 0
        try:
            for row in self.config['AnalyticsProfile']:
                if row.get('client_log_streaming_config'): 
                    stream_logs += 1
            analytics_profile['stream_logs'] = stream_logs       
        except:
            analytics_profile['stream_logs'] = 0     
        return analytics_profile
    ''' dns vs state '''
    def dns_vs_state(self):
        url = self.config['SystemConfiguration'][0]['dns_virtualservice_refs'][0]
        for vs in self.config['VirtualService']:
            if re.search(url, vs['url']):
                # UDF
                dns_vs = OrderedDict()
                if 'analytics_policy' in vs.keys():
                    dns_vs.update({
                    'analytics_policy': vs['analytics_policy']
                    })
                applicationprofile_name = self._lookup_name_from_obj_ref(
                    vs['application_profile_ref'])
                for applicationprofile_obj in self.config['ApplicationProfile']:
                    if applicationprofile_name == applicationprofile_obj['name']:
                        dns_vs['dns_service_profile'] = applicationprofile_obj['dns_service_profile']
        return dns_vs
    ''' search for lingering tenants '''
    def find_lingering_tenants(self):
        tenants_list = []
        for tenant in self.config['Tenant']:
            tenants_list.append(tenant['name'])
        lingering_tenants = list(set(tenants_list) - set(self.k8s.projects_list()) - set(['admin']))
        return lingering_tenants

    def write_report(self, name, report):
        writer = pd.ExcelWriter(name, engine='xlsxwriter')
        pd_report = json_normalize(report)
        df = pd.DataFrame(pd_report).transpose()
        df.to_excel(writer, sheet_name='Main')
        worksheet = writer.sheets['Main']
        worksheet.set_row(0, None, None, {'hidden': True})
        worksheet.set_column('A:B', 40)
        writer.save()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("./avi_healthcheck_report.py --dir")
    parser.add_argument('--dir', type=str, action='store',
    default='')
    args = parser.parse_args()
    avi = Avi(file_path=args.dir)
