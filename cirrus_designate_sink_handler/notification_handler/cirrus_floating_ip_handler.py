# Copyright 2012 Bouvet ASA
# Copyright 2015 Time Warner Cable
#
# Author: Endre Karlson <endre.karlson@bouvet.no>
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

import re

from designate.notification_handler.base import BaseAddressHandler
import designate.notification_handler.base
from designate.openstack.common import log as logging
from designate.objects import Record
import designate.exceptions
from designate.context import DesignateContext
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
    cfg.StrOpt('default_regex', default='\(default\)$'),
    cfg.BoolOpt('require_default_regex', default=False),
    cfg.StrOpt('format', default='%(instance_short_name)s.%(domain)s'),
    cfg.StrOpt('format_fallback',
               default='%(instance_short_name)s-%(octet0)s-%(octet1)s-%(octet2)s-%(octet3)s.%(domain)s'),
], group='handler:cirrus_floating_ip')


class CirrusRecordExists(Exception):
    pass


class CirrusFloatingIPHandler(BaseAddressHandler):
    """Handler for Neutron notifications."""
    __plugin_name__ = 'cirrus_floating_ip'
    __plugin_type__ = 'handler'

    def get_exchange_topics(self):
        exchange = cfg.CONF[self.name].control_exchange

        topics = [topic for topic in cfg.CONF[self.name].notification_topics]

        return (exchange, topics)

    def get_event_types(self):
        return [
            'floatingip.update.end',
            'floatingip.delete.end',
            'port.delete.end',
        ]

    def _get_instance_info(self, kc, port_id):
        """Returns information about the instance associated with the neutron `port_id` given.

        Given a Neutron `port_id`, it will retrieve the device_id associated with
        the port which should be the instance UUID.  It will then retrieve and
        return the instance name and UUID for the instance.  Note that the
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

    def _pick_tenant_domain(self, context, default_regex, require_default_regex, metadata={}):
        """Pick the appropriate domain to create floating ip records in

        If no appropriate domains can be found, it will return `None`.  If a single
        domain is found, it will be returned.  If multiple domains are found, then
        it will look for one where the description matches the regex given, and
        return the first match found.
        """

        tenant_domains = self.central_api.find_domains(context)
        if len(tenant_domains) == 1 and not require_default_regex:
            return tenant_domains[0]

        for domain in tenant_domains:
            if domain.description is not None:
                if re.search(default_regex, domain.description):
                    return domain

        return None

    def _create(self, context, addresses, name_format, extra, domain_id,
                managed_extra, resource_type, resource_id):
        """
        Create a a record from addresses
        :param addresses: Address objects like
                          {'version': 4, 'ip': '10.0.0.1'}
        :param extra: Extra data to use when formatting the record
        :param resource_type: The managed resource type
        :param resource_id: The managed resource ID
        """

        data = extra.copy()
        LOG.debug('Event data: %s' % data)

        names = []
        for addr in addresses:
            event_data = data.copy()
            event_data.update(designate.notification_handler.base.get_ip_data(addr))

            recordset_values = {
                'domain_id': domain_id,
                'name': name_format % event_data,
                'type': 'A' if addr['version'] == 4 else 'AAAA'
            }

            recordset = self._find_or_create_recordset(
                context, **recordset_values)

            # If there is any existing A records for this name, then we don't
            # want to create additional ones, we throw an exception so the
            # caller can retry if appropriate.
            if len(recordset.records) > 0:
                raise CirrusRecordExists('Name already has an A record')

            record_values = {
                'data': addr['address'],
                'managed': True,
                'managed_plugin_name': self.get_plugin_name(),
                'managed_plugin_type': self.get_plugin_type(),
                'managed_extra': managed_extra,
                'managed_resource_type': resource_type,
                'managed_resource_id': resource_id
            }

            LOG.debug('Creating record in %s / %s with values %r' %
                      (domain_id, recordset['id'], record_values))
            self.central_api.create_record(context,
                                           domain_id,
                                           recordset['id'],
                                           Record(**record_values))
            names.append(recordset_values['name'])
        return names

    def _associate_floating_ip(self, context, domain_id, extra, floating_ip_id, floating_ip, port_id):
        """Associate a new A record with a Floating IP

        Try to create an A record using the format specified in the config.  If
        a record with that name already exists, then it will try to create a
        record using the format specified for fallback.  The data passed in as
        the `extra` dict will be used along with the appropriate format to
        generate the FQDN to associate with the A record.

        When creating the record, we store the floating IP uuid in the
        resource_id field and store the port id in the managed_extra field.
        We'll need the port id in case the instance is deleted without the
        floating IP being disassociated first.
        """

        addresses = [{
            'version': 4,
            'address': floating_ip,
        }]
        try:
            names = self._create(context=context,
                                 addresses=addresses,
                                 name_format=cfg.CONF[self.name].format,
                                 extra=extra,
                                 domain_id=domain_id,
                                 managed_extra='portid:%s' % (port_id),
                                 resource_type='a:floatingip',
                                 resource_id=floating_ip_id)
        except (designate.exceptions.DuplicateRecord, CirrusRecordExists):
            LOG.warn('Could not create record for %s using default format, '
                     'trying fallback format' % (extra['instance_name']))
            names = self._create(context=context,
                                 addresses=addresses,
                                 name_format=cfg.CONF[self.name].format_fallback,
                                 extra=extra,
                                 domain_id=domain_id,
                                 managed_extra='portid:%s' % (port_id),
                                 resource_type='a:floatingip',
                                 resource_id=floating_ip_id)
        LOG.info("Created %s to point at %s" % (','.join(names), floating_ip))

    def _disassociate_floating_ip(self, context, floating_ip_id):
        """Remove A records associated with a given floating IP UUID

        Searches for managed A records associated with the given floating IP UUID.
        """

        criterion = {
            'managed': 1,
            'managed_resource_type': 'a:floatingip',
            'managed_resource_id': floating_ip_id,
            'managed_plugin_name': self.get_plugin_name(),
            'managed_plugin_type': self.get_plugin_type(),
        }
        records = self.central_api.find_records(context, criterion=criterion)
        LOG.debug('Found %d records to delete that matched floating ip %s' %
                  (len(records), floating_ip_id))
        for record in records:
            LOG.debug('Deleting record %s with IP %s' % (record['id'], record['data']))
            self.central_api.delete_record(context,
                                           record['domain_id'],
                                           record['recordset_id'],
                                           record['id'])

        LOG.info('Deleted %d records that matched floating ip %s' %
                 (len(records), floating_ip_id))

        return len(records)

    def _disassociate_port_id(self, context, port_id):
        """Remove A records associated with a given Neutron port ID

        Searches for managed A records associated with the given a Neutron port
        ID.  This is called when an instance is deleted and we get a
        port.delete.end event.  Unfortunately we don't have a better place to
        put it, so we look store the portid in the `managed_extra` field.
        """

        criterion = {
            'managed': 1,
            'managed_resource_type': 'a:floatingip',
            'managed_extra': 'portid:%s' % (port_id),
            'managed_plugin_name': self.get_plugin_name(),
            'managed_plugin_type': self.get_plugin_type(),
        }
        records = self.central_api.find_records(context, criterion=criterion)
        LOG.debug('Found %d records to delete that matched port id %s' %
                  (len(records), port_id))
        for record in records:
            LOG.debug('Deleting record %s' % (record['id']))
            self.central_api.delete_record(context,
                                           record['domain_id'],
                                           record['recordset_id'],
                                           record['id'])

        LOG.info('Deleted %d records that matched port_id %s' %
                 (len(records), port_id))

        return len(records)

    def process_notification(self, context, event_type, payload):
        """Process floating IP notifications from Neutron"""

        LOG.info('%s received notification - %s' %
                 (self.get_canonical_name(), event_type))

        # We need a context that will allow us to manipulate records that are
        # flagged as managed, so we can't use the context that was provided
        # with the notification.
        elevated_context = DesignateContext(tenant=context['tenant']).elevated()
        elevated_context.all_tenants = True
        elevated_context.edit_managed_records = True

        # Create an object from the original context so we can use it with the
        # RPC API calls.  We want this limited to the single tenant so we can
        # use it to find their domains.
        orig_context = DesignateContext(tenant=context['tenant']).elevated()

        # When an instance is deleted, we never get a floating IP update event,
        # we just get notified that the underlying port was deleted.  In that
        # case look for it under the other key.
        if event_type.startswith('port.delete'):
            self._disassociate_port_id(context=elevated_context,
                                       port_id=payload['port_id'])

        if event_type.startswith('floatingip.'):
            # A floating IP can only be associated with a single instance at a
            # time, so the first thing we always do is remove any existing
            # association when we get an update.  This is always safe whether
            # or not we're deleting it or reassigning it.
            if 'floatingip' in payload:
                # floatingip.update.end
                floating_ip = payload['floatingip']['floating_ip_address']
                floating_ip_id = payload['floatingip']['id']
            elif 'floatingip_id' in payload:
                # floatingip.delete.end
                floating_ip = None
                floating_ip_id = payload['floatingip_id']

            self._disassociate_floating_ip(context=elevated_context,
                                           floating_ip_id=floating_ip_id,
                                           )

        # If it turns out that the event is an update and it has a fixed ip in
        # the update, then we create the new record.
        if event_type.startswith('floatingip.update'):
            if payload['floatingip']['fixed_ip_address']:
                domain = self._pick_tenant_domain(orig_context,
                                                  default_regex=cfg.CONF[self.name].default_regex,
                                                  require_default_regex=cfg.CONF[self.name].require_default_regex,
                                                  )
                if domain is None:
                    LOG.info('No domains found for tenant %s(%s), ignoring Floating IP update for %s' %
                             (context['tenant_name'], context['tenant_id'], floating_ip))
                else:
                    LOG.debug('Using domain %s(%s) for tenant %s(%s)' %
                              (domain.name, domain.id,
                               context['tenant_name'], context['tenant_id']))

                    kc = keystone_c.Client(token=context['auth_token'],
                                           tenant_id=context['tenant_id'],
                                           auth_url=cfg.CONF[self.name].keystone_auth_uri)

                    port_id = payload['floatingip']['port_id']
                    instance_info = self._get_instance_info(kc, port_id)

                    extra = payload.copy()
                    extra.update({'instance_name': instance_info['name'],
                                  'instance_short_name': instance_info['name'].partition('.')[0],
                                  'domain': domain.name})
                    self._associate_floating_ip(context=elevated_context,
                                                domain_id=domain.id,
                                                extra=extra,
                                                floating_ip_id=floating_ip_id,
                                                floating_ip=floating_ip,
                                                port_id=port_id)
