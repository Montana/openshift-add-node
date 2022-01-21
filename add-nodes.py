#!/usr/bin/env python3

import argparse
import atexit
import datetime
import getpass
import iptools
import jinja2
import os
import six
import ssl
import sys
import uuid

from collections import defaultdict
from six.moves import configparser
from time import time

try:
    import json
except ImportError:
    import simplejson as json


class VMWareAddNode(object):

    __name__ = 'VMWareAddNode'

    openshift_vers = None
    vcenter_host = None
    vcenter_username = None
    vcenter_password = None
    vcenter_template_name = None
    vcenter_folder = None
    vcenter_cluster = None
    vcenter_datacenter = None
    vcenter_resource_pool = None
    vm_dns = None
    vm_gw = None
    vm_netmask = None
    rhsm_activation_key = None
    rhsm_org_id = None
    openshift_sdn = None
    byo_lb = None
    lb_host = None
    byo_nfs = None
    nfs_registry_host = None
    nfs_registry_mountpoint = None
    master_nodes = None
    infra_nodes = None
    app_nodes = None
    vm_ipaddr_start = None
    ocp_hostname_prefix = None
    auth_type = None
    ldap_user = None
    ldap_user_password = None
    ldap_fqdn = None
    deployment_type = None
    console_port = 8443
    rhsm_user = None
    rhsm_password = None
    rhsm_pool = None
    public_hosted_zone = None
    app_dns_prefix = None
    wildcard_zone = None
    inventory_file = 'add-nodes.json'
    support_nodes = None
    node_type = None
    node_number = None
    verbose = 0

    def __init__(self, load=True):

        if load:
            self.parse_cli_args()
            self.read_ini_settings()
            self.create_inventory_file()
        if not self.inventory_file:
            self.create_inventory_file()

        #if create_ocp_vars:
        #    self.create_ocp_vars()
    def parse_cli_args(self):

        parser = argparse.ArgumentParser(
            description='Add new nodes to an existing OCP deployment')
        parser.add_argument('--node_type',
                            action='store',
                            default='app',
                            help='Specify the node label')
        parser.add_argument('--node_number',
                            action='store',
                            default='1',
                            help='Specify the number of nodes to add')
        parser.add_argument(
            '--create_inventory',
            action='store_true',
            help='Helper script to create json inventory file and exit')
        parser.add_argument(
            '--create_ocp_vars',
            action='store_true',
            help=
            'Helper script to modify OpenShift ansible install variables and exit'
        )
        parser.add_argument('--no_confirm',
                            default=None,
                            help='Skip confirmation prompt')
        self.args = parser.parse_args()

    def read_ini_settings(self):
        ''' Read ini file settings '''

        scriptbasename = "ocp-on-vmware"
        defaults = {
            'vmware': {
                'ini_path':
                os.path.join(os.path.dirname(__file__),
                             '%s.ini' % scriptbasename),
                'console_port':
                '8443',
                'deployment_type':
                'openshift-enterprise',
                'openshift_vers':
                'v3_4',
                'vcenter_host':
                '',
                'vcenter_username':
                'administrator@vsphere.local',
                'vcenter_password':
                '',
                'vcenter_template_name':
                'ocp-server-template-2.0.2',
                'vcenter_folder':
                'ocp',
                'vcenter_cluster':
                'devel',
                'vcenter_cluster':
                '',
                'vcenter_resource_pool':
                '/Resources/OCP3',
                'public_hosted_zone':
                '',
                'app_dns_prefix':
                'apps',
                'vm_dns':
                '',
                'vm_gw':
                '',
                'vm_netmask':
                '',
                'vm_network':
                'VM Network',
                'rhsm_user':
                '',
                'rhsm_password':
                '',
                'rhsm_activation_key':
                '',
                'rhsm_org_id':
                '',
                'rhsm_pool':
                'OpenShift Enterprise, Premium',
                'openshift_sdn':
                'openshift-ovs-subnet',
                'byo_lb':
                'no',
                'lb_host':
                'haproxy-',
                'byo_nfs':
                'no',
                'nfs_registry_host':
                'nfs-0',
                'nfs_registry_mountpoint':
                '/exports',
                'master_nodes':
                '3',
                'infra_nodes':
                '2',
                'app_nodes':
                '3',
                'vm_ipaddr_start':
                '',
                'ocp_hostname_prefix':
                '',
                'auth_type':
                'ldap',
                'ldap_user':
                'openshift',
                'ldap_user_password':
                '',
                'node_type':
                self.args.node_type,
                'node_number':
                self.args.node_number,
                'ldap_fqdn':
                ''
            }
        }
        if six.PY3:
            config = configparser.ConfigParser()
        else:
            config = configparser.SafeConfigParser()

        vmware_ini_path = os.environ.get('VMWARE_INI_PATH',
                                         defaults['vmware']['ini_path'])
        vmware_ini_path = os.path.expanduser(
            os.path.expandvars(vmware_ini_path))
        config.read(vmware_ini_path)

        for k, v in defaults['vmware'].iteritems():
            if not config.has_option('vmware', k):
                config.set('vmware', k, str(v))

        self.console_port = config.get('vmware', 'console_port')
        self.deployment_type = config.get('vmware', 'deployment_type')
        self.openshift_vers = config.get('vmware', 'openshift_vers')
        self.vcenter_host = config.get('vmware', 'vcenter_host')
        self.vcenter_username = config.get('vmware', 'vcenter_username')
        self.vcenter_password = config.get('vmware', 'vcenter_password')
        self.vcenter_template_name = config.get('vmware',
                                                'vcenter_template_name')
        self.vcenter_folder = config.get('vmware', 'vcenter_folder')
        self.vcenter_cluster = config.get('vmware', 'vcenter_cluster')
        self.vcenter_datacenter = config.get('vmware', 'vcenter_datacenter')
        self.vcenter_resource_pool = config.get('vmware',
                                                'vcenter_resource_pool')
        self.public_hosted_zone = config.get('vmware', 'public_hosted_zone')
        self.app_dns_prefix = config.get('vmware', 'app_dns_prefix')
        self.vm_dns = config.get('vmware', 'vm_dns')
        self.vm_gw = config.get('vmware', 'vm_gw')
        self.vm_netmask = config.get('vmware', 'vm_netmask')
        self.rhsm_user = config.get('vmware', 'rhsm_user')
        self.rhsm_password = config.get('vmware', 'rhsm_password')
        self.rhsm_activation_key = config.get('vmware', 'rhsm_activation_key')
        self.rhsm_org_id = config.get('vmware', 'rhsm_org_id')
        self.rhsm_pool = config.get('vmware', 'rhsm_pool')
        self.openshift_sdn = config.get('vmware', 'openshift_sdn')
        self.byo_lb = config.get('vmware', 'byo_lb')
        self.lb_host = config.get('vmware', 'lb_host')
        self.byo_nfs = config.get('vmware', 'byo_nfs')
        self.nfs_registry_host = config.get('vmware', 'nfs_registry_host')
        self.nfs_registry_mountpoint = config.get('vmware',
                                                  'nfs_registry_mountpoint')
        self.master_nodes = config.get('vmware', 'master_nodes')
        self.infra_nodes = config.get('vmware', 'infra_nodes')
        self.app_nodes = config.get('vmware', 'app_nodes')
        self.vm_ipaddr_start = config.get('vmware', 'vm_ipaddr_start')
        self.ocp_hostname_prefix = config.get('vmware', 'ocp_hostname_prefix')
        self.auth_type = config.get('vmware', 'auth_type')
        self.ldap_user = config.get('vmware', 'ldap_user')
        self.ldap_user_password = config.get('vmware', 'ldap_user_password')
        self.ldap_fqdn = config.get('vmware', 'ldap_fqdn')
        self.node_type = config.get('vmware', 'node_type')
        self.node_number = config.get('vmware', 'node_number')
        err_count = 0
        required_vars = {
            'public_hosted_zone': self.public_hosted_zone,
            'vcenter_host': self.vcenter_host,
            'vcenter_password': self.vcenter_password,
            'vm_ipaddr_start': self.vm_ipaddr_start,
            'ldap_fqdn': self.ldap_fqdn,
            'ldap_user_password': self.ldap_user_password,
            'vm_dns': self.vm_dns,
            'vm_gw': self.vm_gw,
            'vm_netmask': self.vm_netmask,
            'vcenter_datacenter': self.vcenter_datacenter
        }
        for k, v in required_vars.items():
            if v == '':
                err_count += 1
                print "Missing %s " % k
        if err_count > 0:
            print "Please fill out the missing variables in %s " % vmware_ini_path
            exit(1)
        self.wildcard_zone = "%s.%s" % (self.app_dns_prefix,
                                        self.public_hosted_zone)
        self.support_nodes = 0

        print 'Configured inventory values:'
        for each_section in config.sections():
            for (key, val) in config.items(each_section):
                print '\t %s:  %s' % (key, val)
        if self.byo_nfs == "no":
            self.support_nodes = self.support_nodes + 1
        if self.byo_lb == "no":
            self.support_nodes = self.support_nodes + 1

    def create_inventory_file(self):

        total_nodes = int(self.master_nodes) + int(self.app_nodes) + int(
            self.infra_nodes) + int(self.support_nodes) + int(
                self.args.node_number)
        nodes_remove = int(self.master_nodes) + int(self.app_nodes) + int(
            self.infra_nodes) + int(self.support_nodes)

        ip4addr = []
        for i in range(total_nodes):
            p = iptools.ipv4.ip2long(self.vm_ipaddr_start) + i
            ip4addr.append(iptools.ipv4.long2ip(p))

        unusedip4addr = []
        for i in range(0, int(self.args.node_number)):
            unusedip4addr.insert(0, ip4addr.pop())

        d = {}
        d['host_inventory'] = {}
        for i in range(0, int(self.args.node_number)):
            #determine node_number increment on the number of nodes
            if self.args.node_type == 'app':
                node_ip = int(self.app_nodes) + i
                guest_name = self.args.node_type + '-' + str(node_ip)
            if self.args.node_type == 'infra':
                node_ip = int(self.infra_nodes) + i
                guest_name = self.args.node_type + '-' + str(node_ip)
            if self.ocp_hostname_prefix:
                guest_name = self.ocp_hostname_prefix + guest_name
            d['host_inventory'][guest_name] = {}
            d['host_inventory'][guest_name]['guestname'] = guest_name
            d['host_inventory'][guest_name]['ip4addr'] = unusedip4addr[0]
            d['host_inventory'][guest_name]['tag'] = self.args.node_type
            del unusedip4addr[0]
        with open(self.inventory_file, 'w') as outfile:
            json.dump(d, outfile)

    def create_ocp_vars(self):
        print "hello"

    def launch_refarch_env(region=None,
                           ami=None,
                           no_confirm=False,
                           node_instance_type=None,
                           keypair=None,
                           subnet_id=None,
                           node_sg=None,
                           infra_sg=None,
                           public_hosted_zone=None,
                           app_dns_prefix=None,
                           shortname=None,
                           fqdn=None,
                           deployment_type=None,
                           console_port=443,
                           rhsm_user=None,
                           rhsm_password=None,
                           rhsm_pool=None,
                           containerized=None,
                           node_type=None,
                           iam_role=None,
                           infra_elb_name=None,
                           existing_stack=None,
                           verbose=0):

        if public_hosted_zone is None:
            public_hosted_zone = click.prompt(
                'Hosted DNS zone for accessing the environment')

        if iam_role is None:
            iam_role = click.prompt(
                'Specify the name of the existing IAM Instance Profile')

        if node_sg is None:
            node_sg = click.prompt('Node Security group')

        if node_type in 'infra' and infra_sg is None:
            infra_sg = click.prompt('Infra Node Security group')

        if shortname is None:
            shortname = click.prompt('Hostname of newly created system')

        if existing_stack is None:
            existing_stack = click.prompt(
                'Specify the name of the existing CloudFormation stack')

        if keypair is None:
            keypair = click.prompt(
                'A SSH keypair must be specified or created')

        if subnet_id is None:
            subnet_id = click.prompt(
                'Specify a Private subnet within the existing VPC')

        if deployment_type in ['openshift-enterprise'] and rhsm_user is None:
            rhsm_user = click.prompt("RHSM username?")

        if deployment_type in ['openshift-enterprise'
                               ] and rhsm_password is None:
            rhsm_password = click.prompt("RHSM password?", hide_input=True)

        if deployment_type in ['openshift-enterprise'] and rhsm_pool is None:
            rhsm_pool = click.prompt("RHSM Pool ID or Subscription Name?")

        wildcard_zone = "%s.%s" % (app_dns_prefix, public_hosted_zone)

        fqdn = "%s.%s" % (shortname, public_hosted_zone)

        if node_type in 'infra' and infra_elb_name is None:
            infra_elb_name = click.prompt(
                "Specify the ELB Name used by the router and registry?")

        create_key = "no"
        create_vpc = "no"
        add_node = "yes"

        click.echo('Configured values:')
        click.echo('\tami: %s' % ami)
        click.echo('\tregion: %s' % region)
        click.echo('\tnode_instance_type: %s' % node_instance_type)
        click.echo('\tkeypair: %s' % keypair)
        click.echo('\tsubnet_id: %s' % subnet_id)
        click.echo('\tnode_sg: %s' % node_sg)
        click.echo('\tinfra_sg: %s' % infra_sg)
        click.echo('\tconsole port: %s' % console_port)
        click.echo('\tdeployment_type: %s' % deployment_type)
        click.echo('\tpublic_hosted_zone: %s' % public_hosted_zone)
        click.echo('\tapp_dns_prefix: %s' % app_dns_prefix)
        click.echo('\tapps_dns: %s' % wildcard_zone)
        click.echo('\tshortname: %s' % shortname)
        click.echo('\tfqdn: %s' % fqdn)
        click.echo('\trhsm_user: %s' % rhsm_user)
        click.echo('\trhsm_password: *******')
        click.echo('\trhsm_pool: %s' % rhsm_pool)
        click.echo('\tcontainerized: %s' % containerized)
        click.echo('\tnode_type: %s' % node_type)
        click.echo('\tiam_role: %s' % iam_role)
        click.echo('\tinfra_elb_name: %s' % infra_elb_name)
        click.echo('\texisting_stack: %s' % existing_stack)
        click.echo("")

        if not no_confirm:
            click.confirm('Continue using these values?', abort=True)

        playbooks = [
            'playbooks/infrastructure.yaml', 'playbooks/add-node.yaml'
        ]

        for playbook in playbooks:

            devnull = '> /dev/null'

            if verbose > 0:
                devnull = ''

            command = 'inventory/aws/hosts/ec2.py --refresh-cache %s' % (
                devnull)
            os.system(command)

            command = 'rm -rf .ansible/cached_facts'
            os.system(command)

            command = 'ansible-playbook -i inventory/aws/hosts -e \'region=%s \
            ami=%s \
            keypair=%s \
            add_node=yes \
            subnet_id=%s \
            node_sg=%s \
            infra_sg=%s \
            node_instance_type=%s \
            public_hosted_zone=%s \
            wildcard_zone=%s \
            shortname=%s \
            fqdn=%s \
            console_port=%s \
            deployment_type=%s \
            rhsm_user=%s \
            rhsm_password=%s \
            rhsm_pool=%s \
            containerized=%s \
            node_type=%s \
            iam_role=%s \
            key_path=/dev/null \
            infra_elb_name=%s \
            create_key=%s \
            create_vpc=%s \
            stack_name=%s \' %s' % (
                region, ami, keypair, subnet_id, node_sg, infra_sg,
                node_instance_type, public_hosted_zone, wildcard_zone,
                shortname, fqdn, console_port, deployment_type, rhsm_user,
                rhsm_password, rhsm_pool, containerized, node_type, iam_role,
                infra_elb_name, create_key, create_vpc, existing_stack,
                playbook)

            if verbose > 0:
                command += " -" + "".join(['v'] * verbose)
                click.echo('We are running: %s' % command)

            status = os.system(command)
            if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
                return os.WEXITSTATUS(status)


if __name__ == '__main__':

    VMWareAddNode()
