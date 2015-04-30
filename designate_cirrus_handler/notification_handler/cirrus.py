import re

from designate.notification_handler.base import BaseAddressHandler
from designate.openstack.common import log as logging
import designateclient.exceptions
import designateclient.v1 as designate_c
from designateclient.v1.records import Record as designate_record
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
    cfg.StrOpt('keystone_auth_uri', default=None),
    cfg.StrOpt('region', default=None),
    cfg.StrOpt('default_regex', default='\(default\)$'),
], group='handler:cirrus_floatingip')


def get_instance_info(kc, port_id):
    """Returns information about the instnace associated with the neutron `port_id` given.

    Given a Neutron `port_id`, it will retrieve the device_id associated with
    the port which should be the instance UUID.  It will then retrieve and
    return the instance name and tenant_id for the instance.  Note that the
    `port_id` must the one associated with the instance, not the floating IP.
    Neutron floating ip notifications will contain the instance's port_id.

    """

    neutron_endpoint = kc.service_catalog.url_for(service_type='network',
                                                  endpoint_type='internalURL')
    nc = neutron_c.Client(token=kc.auth_token,
                          tenant_id=kc.auth_tenant_id,
                          endpoint_url=neutron_endpoint)
    port_details = nc.show_port(port_id)
    instance_id = port_details['port']['device_id']
    instance_info = {'id': instance_id}

    nova_endpoint = kc.service_catalog.url_for(service_type='compute',
                                               endpoint_type='internalURL')
    nvc = nova_c.Client(auth_token=kc.auth_token,
                        tenant_id=kc.auth_tenant_id,
                        bypass_url=nova_endpoint)
    server_info = nvc.servers.get(instance_id)
    instance_info['name'] = server_info.name
    instance_info['tenant_id'] = server_info.tenant_id

    return instance_info


def pick_tenant_domain(designate_client, regex, metadata={}):
    """Pick the appropriate domain to create floating ip records in

    If no appropriate domains can be found, it will return `None`.  If a single
    domain is found, it will be returned.  If multiple domains are found, then
    it will look for one where the description matches the regex given, and
    return the first match found.
    """

    tenant_domains = designate_client.domains.list()
    if len(tenant_domains) == 0:
        return None
    elif len(tenant_domains) == 1:
        return tenant_domains[0]

    for domain in tenant_domains:
        if 'description' in domain and domain['description'] is not None:
            if re.search(regex, domain['description']):
                return domain


def create_record(designate_client, domain_id, name, floating_ip):
    """Creates a new A record for a floating ip without error handling

    This is intended to be called by `associate_floating_ip`, and that the
    caller will handle any errors that occur.
    """

    record = {
        'name': name,
        'type': 'A',
        'data': floating_ip,
    }
    record = designate_record(record)

    designate_client.records.create(domain_id, record)
    LOG.info('Creating %s record for FIP %s' % (name, floating_ip))


def associate_floating_ip(designate_client, domain_id, name, floating_ip):
    """Associate a new A record with a Floating IP

    Try to create an A record using a FQDN provide as `name` in the domain
    specified by the UUID provided by `domain_id` that points to the IP address
    provided as `floating_ip`.  If the FQDN provided already exists then the IP
    address will be appended to the hostname portion of the FQDN.  The IP
    address will have the periods replaced with dashes, and be separated from
    the original name with another dash.
    """

    try:
        create_record(designate_client, domain_id, name, floating_ip)
    except designateclient.exceptions.Conflict:
        # If there is already a client with this name, then we append the ip
        # address to the end, with the dots converted to dashes
        octets = [int(x) for x in floating_ip.split('.')]
        fqdnparts = name.split('.')
        fqdnparts[0] = "%s-%d-%d-%d-%d" % tuple([fqdnparts[0]] + octets)
        new_name = '.'.join(fqdnparts)
        LOG.warn('Could not create %s, trying %s instead' % (name, new_name))
        create_record(designate_client, domain_id, new_name, floating_ip)


def purge_floating_ip_in_domain(designate_client, domain, floating_ip):
    """Remove all A records that match the `floating_ip` in the given `domain`

    The `domain` parameter must be a dict as returned from the designate client
    API.  This will return the number of records removed.
    """

    LOG.debug('Looking for A records matching %s in %s(%s)' % (floating_ip, domain['name'], domain['id']))
    delete_count = 0
    for record in designate_client.records.list(domain['id']):
        if record['type'] == 'A' and record['data'] == floating_ip:
            LOG.info('Deleting %s A record (matches floating IP %s)' % (record['name'], floating_ip))
            designate_client.records.delete(domain['id'], record['id'])
            delete_count += 1
    return delete_count


def disassociate_floating_ip(designate_client, floating_ip):
    """Remove matching A records in all domains owned by the tenant

    Iterate over all domains owned by the tenant associated with
    `designate_client` and remove any that have A records that point to
    `floating_ip`.
    """

    tenant_domains = designate_client.domains.list()
    delete_count = 0
    for domain in tenant_domains:
        delete_count += purge_floating_ip_in_domain(designate_client, domain, floating_ip)
    LOG.info('Deleted %d records that matched %s' % (delete_count, floating_ip))


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
        """Process floating IP notifications from Neutron"""
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
    print(get_instance_info(kc, args.port_id))


def test_pick_tenant_domain(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    print(pick_tenant_domain(designate_client=dc, regex=args.domain_desc_regex))


def test_associate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    associate_floating_ip(desigate_client=dc, domain_id=args.domain_id, name=args.name, floating_ip=args.ip_address)


def test_disassociate_floating_ip(kc, args):
    designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                    endpoint_type='internalURL')
    dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                            endpoint=designate_endpoint)
    disassociate_floating_ip(client=dc, floating_ip=args.ip_address)


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
