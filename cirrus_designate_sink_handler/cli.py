# Copyright 2015 Time Warner Cable
#
# Author: Clayton O'Neill <clayton.oneill@twcable.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import cirrus_designate_sink_handler.notification_handler.cirrus_floating_ip_handler as cirrus
from designate.openstack.common import log as logging
from designate.utils import find_config
from designate.context import DesignateContext
from designate import rpc
from designate import policy
from keystoneclient.v2_0 import client as keystone_c
from oslo.config import cfg

PROG = 'designate-cirrus-sink'
LOG = logging.getLogger(__name__)


def env(*vars, **kwargs):
    """Search for the first defined of possibly many env vars

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.

    """
    import os

    for v in vars:
        value = os.environ.get(v)
        if value:
            return value
    return kwargs.get('default', '')


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="Test Cirrus notification handler")
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='valid subcommands',
                                       help='additional help')

    parser.add_argument("-c", "--config-file",
                        dest='config_file',
                        default='/etc/designate/designate.conf',
                        help='Config file to load'
                             'Defaults to /etc/designate/designate.conf')
    parser.add_argument("--endpoint-type",
                        metavar='<endpoint-type>',
                        dest='endpoint_type',
                        default='publicURL',
                        help='Type of URL from the Keystone Catalog to test. '
                             'Defaults to publicURL')
    parser.add_argument("--os-user-name",
                        metavar='<user-name>',
                        dest="username",
                        default=env('OS_USERNAME'),
                        help='Name used for authentication with the '
                             'OpenStack Identity service. '
                             'Defaults to env[OS_USERNAME].')
    parser.add_argument("--os-password",
                        metavar='<password>',
                        dest='password',
                        default=env('OS_PASSWORD'),
                        help='Password used for authentication with the '
                             'OpenStack Identity service. '
                             'Defaults to env[OS_PASSWORD].')
    parser.add_argument("--os-tenant-name",
                        metavar='<tenant-name>',
                        dest='tenantname',
                        default=env('OS_TENANT_NAME'),
                        help='Tenant to request authorization on. '
                             'Defaults to env[OS_TENANT_NAME].')
    parser.add_argument("--os-region-name",
                        metavar='<region-name>',
                        dest='regionname',
                        default=env('OS_REGION_NAME'),
                        help='Specify the region to use. '
                             'Defaults to env[OS_REGION_NAME].')
    parser.add_argument("--os-auth-url",
                        metavar='<auth-url>',
                        dest='authurl',
                        default=env('OS_AUTH_URL'),
                        help='Specify the Identity endpoint to use for '
                             'authentication. '
                             'Defaults to env[OS_AUTH_URL].')

    gii_parser = subparsers.add_parser('get-instance-info',
                                       help='Get instance info from Neutron port-id')
    gii_parser.add_argument('--port-id', required=True,
                            help='Neutron port-id to get info for')
    gii_parser.set_defaults(func=test_get_instance_info)

    ptd_parser = subparsers.add_parser('pick-tenant-domain',
                                       help='Given a tenant-id, return the '
                                            'domain name to put FIP records in')
    ptd_parser.add_argument('--tenant-id', required=True,
                            help='ID of tenant to look up in Designate')
    ptd_parser.add_argument('--domain-desc-regex', default='\(default\)$',
                            metavar='REGEX',
                            help='Regex to match against designate domain description when '
                                 'picking among multiples.  Defaults to \'\(default\)$\'')
    ptd_parser.set_defaults(func=test_pick_tenant_domain)

    afi_parser = subparsers.add_parser('associate-floating-ip',
                                       help='Given a IP address and domain ID, create a new record in the default domain')
    afi_parser.add_argument('--domain-id', required=True,
                            help='UUID of designate-domain to create record in')
    afi_parser.add_argument('--domain-name', required=True,
                            help='Name of designate-domain to create record in')
    afi_parser.add_argument('--name', required=True,
                            help='Name of new record to create')
    afi_parser.add_argument('--ip-address', required=True,
                            help='IP Address to associate with record')
    afi_parser.add_argument('--ip-uuid', required=True,
                            help='Floating IP UUID to associate with record')
    afi_parser.add_argument('--port-id', required=True,
                            help='Neutron port ID to associate with record')
    afi_parser.set_defaults(func=test_associate_floating_ip)

    dfi_parser = subparsers.add_parser('disassociate-floating-ip',
                                       help='Given a UUID and IP address, remove any A '
                                            'records in any tenant domains that match')
    dfi_parser.add_argument('--ip-id', required=True,
                            help='Floating IP UUID to disassociate with records found')
    dfi_parser.add_argument('--ip-address', required=True,
                            help='Floating IP Address to disassociate with records found')
    dfi_parser.set_defaults(func=test_disassociate_floating_ip)

    return parser.parse_args()


def test_get_instance_info(kc, handler, context, args):
    print(handler._get_instance_info(kc, args.port_id))


def test_pick_tenant_domain(kc, handler, context, args):
    print(handler._pick_tenant_domain(context=context,
                                      regex=args.domain_desc_regex
                                      ).items())


def test_associate_floating_ip(kc, handler, context, args):
    extra = {
        'instance_name': args.name,
        'domain': args.domain_name,
    }
    handler._associate_floating_ip(context, domain_id=args.domain_id,
                                   extra=extra,
                                   floating_ip_id=args.ip_uuid,
                                   floating_ip=args.ip_address,
                                   port_id=args.port_id)


def test_disassociate_floating_ip(kc, handler, context, args):
    handler._disassociate_floating_ip(floating_ip_id=args.ip_id,
                                      floating_ip=args.ip_address)


def load_config(filename):
    config_files = find_config('%s.conf' % 'designate')
    cfg.CONF(args=[], project='designate', prog=PROG,
             default_config_files=config_files)


def main():
    args = parse_args()
    logging.setup('cirrus_floatingip')
    LOG.logger.setLevel('DEBUG')
    load_config(args.config_file)

    kc = keystone_c.Client(
        username=args.username,
        password=args.password,
        tenant_name=args.tenantname,
        auth_url=args.authurl,
        endpoint_type=args.endpoint_type,
        region_name=args.regionname)

    policy.init()
    rpc.init(cfg.CONF)
    context = DesignateContext.get_admin_context(tenant=kc.auth_tenant_id)

    handler = cirrus.CirrusFloatingIPHandler()

    args.func(kc, handler, context, args)

if __name__ == "__main__":
    main()
