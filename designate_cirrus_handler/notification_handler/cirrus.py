import re

from designate.notification_handler.base import BaseAddressHandler
from designate.openstack.common import log as logging
import designateclient.exceptions
import designateclient.v1 as designate_c
from keystoneclient.v2_0 import client as keystone_c
from neutronclient.v2_0 import client as neutron_c
from novaclient.v2 import client as nova_c
from oslo.config import cfg

LOG = logging.getLogger(__name__)

cfg.CONF.register_group(cfg.OptGroup(
    name='handler:cirrus_floatingip',
    title="Configuration for Cirrus Notification Handler"
))

cfg.CONF.register_opts([
    cfg.ListOpt('notification-topics', default=['notifications']),
    cfg.StrOpt('control-exchange', default='neutron'),
    cfg.StrOpt('domain-id', default=None),
    cfg.StrOpt('format', default=None),
    cfg.StrOpt('keystone_authurl', default=None),
    cfg.StrOpt('region', default=None),
    cfg.StrOpt('default_regex', default='\(default\)$'),
], group='handler:cirrus_floatingip')


def get_instance_info(auth_url, tenant_id, token, port_id):
    kc = keystone_c.Client(token=token, tenant_id=tenant_id,
                           auth_url=auth_url)

    kc.service_catalog.get_endpoints()
    neutron_endpoint = kc.service_catalog.url_for(service_type='network',
                                                  endpoint_type='internalURL')
    nc = neutron_c.Client(token=token, endpoint_url=neutron_endpoint)
    port_details = nc.show_port(port_id)
    instance_id = port_details['port']['device_id']
    instance_info = {'id': instance_id}

    nova_endpoint = kc.service_catalog.url_for(service_type='compute',
                                               endpoint_type='internalURL')
    nvc = nova_c.Client(auth_token=token, bypass_url=nova_endpoint)
    server_info = nvc.servers.get(instance_id)
    instance_info['name'] = server_info.name
    instance_info['tenant_id'] = server_info.tenant_id

    return instance_info


def pick_tenant_domain(client, regex, metadata={}):
    tenant_domains = client.domains.list()
    if len(tenant_domains) == 0:
        return None
    elif len(tenant_domains) == 1:
        return tenant_domains[0]

    for domain in tenant_domains:
        if 'description' in domain and domain['description'] is not None:
            if re.search(regex, domain['description']):
                return domain


def create_record(client, domain_id, name, fip):
    record = {
        'name': name,
        'type': 'A',
        'data': fip,
    }
    if isinstance(client, designate_c.Client):
        from designateclient.v1.records import Record
        record = Record(record)

    client.records.create(domain_id, record)
    LOG.info('Creating %s record for FIP %s' % (name, fip))


def associate_floating_ip(client, domain_id, name, fip):
    try:
        create_record(client, domain_id, name, fip)
    except designateclient.exceptions.Conflict:
        # If there is already a client with this name, then we append the ip
        # address to the end, with the dots converted to dashes
        octets = [int(x) for x in fip.split('.')]
        fqdnparts = name.split('.')
        fqdnparts[0] = "%s-%d-%d-%d-%d" % tuple([fqdnparts[0]] + octets)
        new_name = '.'.join(fqdnparts)
        LOG.warn('Could not create %s, trying %s instead' % (name, new_name))
        create_record(client, domain_id, new_name, fip)


def purge_fip_in_domain(client, domain, fip):
    LOG.debug('Looking for A records matching %s in %s(%s)' % (fip, domain['name'], domain['id']))
    delete_count = 0
    for record in client.records.list(domain['id']):
        if record['type'] == 'A' and record['data'] == fip:
            LOG.info('Deleting %s A record (matches FIP %s)' % (record['name'], fip))
            client.records.delete(domain['id'], record['id'])
            delete_count += 1
    return delete_count


def disassociate_floating_ip(client, fip):
    tenant_domains = client.domains.list()
    delete_count = 0
    for domain in tenant_domains:
        delete_count += purge_fip_in_domain(client, domain, fip)
    LOG.info('Deleted %d records that matched %s' % (delete_count, fip))


class CirrusFloatingHandler(BaseAddressHandler):
    """Handler for Neutron's notifications."""
    __plugin_name__ = 'cirrus_floatingip'

    def get_exchange_topics(self):
        exchange = cfg.CONF[self.name].control_exchange

        topics = [topic for topic in cfg.CONF[self.name].notification_topics]

        return (exchange, topics)

    def get_event_types(self):
        return [
            'floatingip.update.end',
            'floatingip.delete.start'
        ]

    def process_notification(self, context, event_type, payload):
        LOG.info('%s received notification - %s' %
                 (self.get_canonical_name(), event_type))
        print(payload)

        if event_type.startswith('floatingip.delete'):
            self._delete(resource_id=payload['floatingip_id'],
                         resource_type='floatingip')
        elif event_type.startswith('floatingip.update'):
            if payload['floatingip']['fixed_ip_address']:
                address = {
                    'version': 4,
                    'address': payload['floatingip']['floating_ip_address']}
                self._create([address], payload,
                             resource_id=payload['floatingip']['id'],
                             resource_type='floatingip')
            elif not payload['floatingip']['fixed_ip_address']:
                self._delete(resource_id=payload['floatingip']['id'],
                             resource_type='floatingip')


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
    print(get_instance_info(args.authurl, kc.auth_tenant_id, kc.auth_token, args.port_id))


def test_pick_tenant_domain(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    print(pick_tenant_domain(client=dc, regex=args.domain_desc_regex))


def test_associate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    associate_floating_ip(client=dc, domain_id=args.domain_id, name=args.name, fip=args.ip_address)


def test_disassociate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    disassociate_floating_ip(client=dc, fip=args.ip_address)


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
