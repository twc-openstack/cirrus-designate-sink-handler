# Introduction

The `cirrus-designate-sink-handler` python package provides a Designate Sink
handler for Neutron events.  This handler has the following features:

* Create and delete records in Designate when Neutron floating IPs are
  associated and disassociated with an instance.  This includes deleting the
  records when the instance is deleted.

* Flexible formatting of record names that allows including instance name, UUID
  and IP address into the name.

* Records are created in the user's project (or tenant) domains, with support
  for populating records into a specific domain if multiple domains are
  provisioned.

This Designate Sink handler was developed against the Juno version of
Designate, and due to API changes is not expected to yet work against the Kilo
release without changes.

# How does it work?

Designate Sink is configured to load one or more handlers.  Those handlers are
configured to ask the Sink to listen on one or more topics for one or more
events.  In the case of this handler, it asks the Sink to listen on the
configured topic for Neutron topics.  Specifically, it listens to the following
events:

 * floatingip.update.end
 * floatingip.delete.start
 * port.delete.end

Neutron generates events for the beginning and end of all CRUD events for the
objects that it manages.  The `start` events indicates that it has received the
a request and the `end` events indicate that the request has been successfully
completed.

When any floating IP update is received, the handler first removes any existing
A records that have been tagged with the floating IP UUID.  For a disassociate
request, this is the only work that's needed.  For the associate, this gives a
clean environment in case the record is being moved directly from one instance
to another.

When this handler receives a `floatingip.update.end` event, it checks to see if
it's an associate event by looking to see if there is a fixed IP address in the
event.  If that is the case then it creates a new A record in the project (or
tenant) domain that has been configured as described below.  The new record
that is created is a "managed record" that has the floating IP UUID and port ID
stored with the record.

In order to build a name for the A record based on the instance name, the
handler will take the port ID in the associate event and request information
from Neutron.  The port ID in the event will be that of the instance the
floating IP is being associated to.  The device ID associated with this port
will be the ID of the instance.  The handler just has to retrieve the instance
name from Nova based on the instance ID.

Lastly, when an instance is deleted, Neutron doesn't generate a disassociate
event, but instead deletes the port in question.  In this case Neutron only
emits a `port.delete` event.  When it recieves a `port.delete.end` event, the
handler will delete all records (normally one) that are associated with the
instance's port ID.

Examples of the events discussed can be found in the events/ directory in the repository.

# Installing

You can install this plugin via pip from GitHub using the following command:

```
pip install -e https://github.com/twc-openstack/cirrus-designate-sink-handler.git@master#egg=cirrus-designate-sink-handler
```

# Configuration

Once installed, you will need to enable the handler by adding it to your
Designate configuration file as shown below:

```
[service:sink]
# List of notification handlers to enable, configuration of these needs to
# correspond to a [handler:my_driver] section below or else in the config
enabled_notification_handlers = cirrus_floating_ip
```

The following configuration options can be set in the
`[handler:cirrus_floating_ip]` section of your Designate configuration file.

## notification-topics
Default: `notifications`

This is the notification topic you have configured Neutron to emit
notifications on for Designate Sink to consume.  The default matches the
default in Neutron, but it's recommended that you configure this to be
something more informative like `neutron_to_designate_sink`.  This notification
topic cannot be shared with any other consumers, since notifications can only
be consumed once.  This must match what is configured in Neutron.

## control-exchange
**Default**: `neutron`

This is the exchange that Neutron is configured with.  This must match what is
configured in Neutron.

## keystone_auth_uri

**Required**

This is the URI of your keystone endpoint you wish to use for token validation
and endpoint discovery.  This will be used to find your Neutron and Nova
endpoints.  Most people will want to set this to the internalURL of the
Keystone service.

## default_regex

**Default**: `(default)$`

If multiple domains are configured for a given project (or tenant), then this
regex will be used to pick which one to create records in.  The regex will be
matched against each domain's description field, in the order that the domains
are returned from Designate.  If the regex is not anchored then it can match
anywhere in the description field.  If no matches are found, then the handler
will not create a record.  If there is a single domain for the project (or
tenant) then it will always be picked regardless of its description.

## format

**Default**: `%(instance_name)s.%(domain)s`

When creating new records, this value will be used as a Python format string to
determine the name to use.  The following variables are available for
substitution:

 * instance_name - name of the instance being associated with the floating IP

 * domain - domain the record will be created in

 * octet0, octet1, octet2, octet3 - This will be populated by splitting the
   floating IP on the dots.  For example, for an IP address 1.2.3.4, `octet0`
   would be 1, `octet1` would be 2, `octet2` would be 3 and `octet3` would be 4.

## format_fallback

**Default**: `%(instance_name)s-%(octet0)s-%(octet1)s-%(octet2)s-%(octet3)s.%(domain)s`

When creating the record, if the handler detects there is already an A record
that exists with the name that was generated using the `format` pattern, then
it will fallback to the pattern specified with `format_fallback`.  The default
incorporates the floating IP address, which should be unique, guaranteeing no
conflicts.  The same variable are available for substitution as documented
above for the `format` option.

# Notes

This handler creates managed records in the Designate storage backend.
End-users will not be able to modify or delete managed records.  Additional
information about the original floating IP UUID and the Neutron port-id are
stored along with the records in the `managed-resource-id` and `managed_extra`
fields respectively.

Currently the Juno release of Designate provides no mechanism via the REST API
to update or delete managed records even for admin users.

# Credits

This handler was originally based on the example Neutron handler distributed
with the Juno release of Designate.

