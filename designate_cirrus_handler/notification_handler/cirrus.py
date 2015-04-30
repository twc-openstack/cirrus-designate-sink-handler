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
    LOG.debug('Instance id for port id %s is %s' % (port_id, instance_id))

    nova_endpoint = kc.service_catalog.url_for(service_type='compute',
                                               endpoint_type='internalURL')
    nvc = nova_c.Client(auth_token=kc.auth_token,
                        tenant_id=kc.auth_tenant_id,
                        bypass_url=nova_endpoint)
    server_info = nvc.servers.get(instance_id)
    instance_info['name'] = server_info.name
    LOG.debug('Instance name for id %s is %s' % (instance_id, server_info.name))

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

        kc = keystone_c.Client(token=context['auth_token'],
                               tenant_id=context['tenant_id'],
                               auth_url=cfg.CONF[self.name].keystone_auth_uri)

        designate_endpoint = kc.service_catalog.url_for(service_type='dns',
                                                        endpoint_type='internalURL')
        dc = designate_c.Client(token=kc.auth_token, tenant_id=kc.auth_tenant_id,
                                endpoint=designate_endpoint)

        if event_type.startswith('floatingip.delete'):
            floating_ip = payload['floatingip']['floating_ip_address']
            disassociate_floating_ip(designate_client=dc,
                                     floating_ip=floating_ip)
        elif event_type.startswith('floatingip.update'):
            floating_ip = payload['floatingip']['floating_ip_address']
            if payload['floatingip']['fixed_ip_address']:
                port_id = payload['floatingip']['port_id']
                instance_info = get_instance_info(kc, port_id)
                domain = pick_tenant_domain(designate_client=dc,
                                            regex=cfg.CONF[self.name].default_regex)
                if domain is None:
                    LOG.info('No domains found for tenant %s(%s), ignoring Floating IP update for %s' %
                             (context['tenant_name'], context['tenant_id'], floating_ip))
                else:
                    LOG.debug('Using domain %s(%s) for tenant %s(%s)' %
                              (domain['name'], domain['id'],
                               context['tenant_name'], context['tenant_id']))

                    name = instance_info['name'] + '.' + domain['name']
                    associate_floating_ip(designate_client=dc,
                                          domain_id=domain['id'],
                                          name=name,
                                          floating_ip=floating_ip)
            elif not payload['floatingip']['fixed_ip_address']:
                disassociate_floating_ip(designate_client=dc,
                                         floating_ip=floating_ip)
