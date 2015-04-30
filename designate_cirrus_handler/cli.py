import designate_cirrus_handler.notification_handler.cirrus as cirrus
from designate.openstack.common import log as logging
import designateclient.v1 as designate_c
from keystoneclient.v2_0 import client as keystone_c

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
    afi_parser.add_argument('--name', required=True,
                            help='Name of new record to create')
    afi_parser.add_argument('--ip-address', required=True,
                            help='IP Address to associate with record')
    afi_parser.set_defaults(func=test_associate_floating_ip)

    dfi_parser = subparsers.add_parser('disassociate-floating-ip',
                                       help='Given a IP address, remove any A '
                                            'records in any tenant domains that match')
    dfi_parser.add_argument('--ip-address', required=True,
                            help='IP Address to disassociate with records found')
    dfi_parser.set_defaults(func=test_disassociate_floating_ip)

    return parser.parse_args()


def test_get_instance_info(kc, args):
    print(cirrus.get_instance_info(kc, args.port_id))


def test_pick_tenant_domain(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    print(cirrus.pick_tenant_domain(designate_client=dc, regex=args.domain_desc_regex))


def test_associate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    cirrus.associate_floating_ip(desigate_client=dc, domain_id=args.domain_id,
                                 name=args.name, floating_ip=args.ip_address)


def test_disassociate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    cirrus.disassociate_floating_ip(client=dc, floating_ip=args.ip_address)


def main():
    args = parse_args()
    logging.setup('cirrus_floatingip')
    LOG.logger.setLevel('DEBUG')

    kc = keystone_c.Client(
        username=args.username,
        password=args.password,
        tenant_name=args.tenantname,
        auth_url=args.authurl,
        endpoint_type=args.endpoint_type,
        region_name=args.regionname)

    args.func(kc, args)

if __name__ == "__main__":
    main()
