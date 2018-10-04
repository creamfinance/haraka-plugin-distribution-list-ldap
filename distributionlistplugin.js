const ldap = require('ldapjs');
let Address;

class DistributionListPlugin {
    constructor (plugin, require) {
        this.plugin = plugin;
        Address = require('address-rfc2821').Address;
        this.outbound = require('outbound');

        this.lookup_table = {};
        this.is_loaded = false;
        this.ldap_loading_interval = null;
    }

    register () {
        this.plugin.register_hook('rcpt', this.onRcpt.bind(this));
        this.plugin.register_hook('queue', this.onQueue.bind(this));

        this.plugin.config.get('distribution-list-ldap.yaml', 'yaml', () => {
            this.loadConfig();
        });

        this.loadConfig();
    }

    loadConfig () {
        this.cfg = this.plugin.config.get('distribution-list-ldap.yaml');

        this.loadLdapConfiguration();

        if (this.ldap_loading_interval) {
            clear_interval(this.ldap_loading_interval);
        }

        var interval = (this.cfg.settings.refresh_interval || 600) * 1000;
        this.ldap_loading_interval = setInterval(this.loadLdapConfiguration.bind(this), interval);
        this.plugin.loginfo('Set reloading interval to ' + interval + ' ms');

    }

    async getLdapConnection () {
        return new Promise((resolve, reject) => {
            if (this.ldapConnection) {
                return this.ldapConnection;
            }

            const conn = ldap.createClient({ url: this.cfg.settings.url });

            conn.bind(this.cfg.settings.bind.dn, this.cfg.settings.bind.pw, (err) => {
                if (err) {
                    return reject(err);
                }

                resolve(conn);
            });
        });
    }

    async ldapSearch (client, filter) {
        const rawTypes = [ 'objectGUID' ];
        const arrayTypes = [ 'member', 'proxyAddresses' ]

        return new Promise((resolve, reject) => {
            const options = { scope: 'sub', attributes: [ 'dn', 'objectGUID', 'member', 'mail', 'proxyAddresses', 'groupType' ], filter: filter };

            client.search(this.cfg.settings.basedn, options, (err, emitter) => {
                if (err) {
                    return reject(err);
                }

                const items = [];

                emitter.on('searchEntry', (entry) => {
                    const object = { dn: entry.dn };

                    for (let i = 0; i < entry.attributes.length; i++) {
                        const attr = entry.attributes[i];

                        if (rawTypes.indexOf(attr.type) !== -1) {
                            object[attr.type] = attr.buffers[0].toString('hex');
                        } else if (arrayTypes.indexOf(attr.type) !== -1) {
                            object[attr.type] = (attr.vals instanceof Array ? attr.vals : [ attr.vals ]);
                        } else {
                            object[attr.type] = attr.vals[0];
                        }
                    }

                    items.push(object);
                });

                emitter.on('error', (err) => {
                    reject(err);
                });

                emitter.on('end', (result) => {
                    resolve(items);
                });
            });
        });
    }

    assignEmailToObject(container, object, mail) {
        // No op, we don't do anything if empty
        if (!mail) {
            return;
        }

        if (mail in container) {
            this.log('Object has double address: ', mail, object);
        } else {
            container[mail] = object;
        }
    }

    async loadLdapConfiguration () {
        try {
            const time_start = Date.now();

            const client = await this.getLdapConnection();

            // load all groups
            const groups = await this.ldapSearch(client, this.cfg.groups.filter);

            // load all users
            const users = await this.ldapSearch(client, this.cfg.users.filter);

            const time_assign = Date.now()

            // build dictionary of groups:
            const final_emails = {};
            const dn_map_users = {};

            // build dictionary for users
            for (let i = 0; i < users.length; i++) {
                const user = users[i];

                dn_map_users[user.dn] = user;

                this.assignEmailToObject(final_emails, user, user.mail);

                if (user.proxyAddresses) {
                    for (let x = 0; x < user.proxyAddresses.length; x++) {
                        this.assignEmailToObject(final_emails, user, user.proxyAddresses[x]);
                    }
                }
            }

            for (let i = 0; i < groups.length; i++) {
                const group = groups[i];

                this.assignEmailToObject(final_emails, group, group.mail);

                if (group.proxyAddresses) {
                    for (let x = 0; x < group.proxyAddresses.length; x++) {
                        this.assignEmailToObject(final_emails, group, group.proxyAddresses[x]);
                    }
                }

                // Security Groups don't resolve to all members, only distribution lists
                if (group.member && (((group.groupType & 0x80000000) >>> 0) == 0)) {
                    group.members_resolved = [];
                    group.is_distribution_list = true;

                    for (let x = 0; x < group.member.length; x++) {
                        if (group.member[x] in dn_map_users) {
                            group.members_resolved.push(dn_map_users[group.member[x]].mail);
                        } else {
                            this.plugin.logerror('Unable to find member in users list: ', group.dn, group.member[x]);
                        }
                    }
                } else {
                    group.is_distribution_list = false;
                }
            }

            const time_done = Date.now();

            this.plugin.logdebug('Ldap Configuration Update took: ' + (time_done - time_start) + ' ms, Assign: ' + (time_done - time_assign) + ' ms');

            this.lookup_table = final_emails;
            this.is_loaded = true;
        } catch (err) {
            console.log(err);
        }
    }

    onQueue (next, connection, params) {
        const plugin = this.plugin;
        const txn = connection.transaction;
        const results = txn.results.get('distribution-list-ldap');

        if (!results || !results.recipients) {
            return next();
        }

        const recipients = results.recipients;
        const final_rcpt = [];
        let filter = '';

        connection.logdebug(plugin, recipients);

        // there's always only one recipient
        var recipient = recipients[0];

        if (!recipient) {
            return next();
        }

        if (!recipient.is_distribution_list) {
            return next(OK);
        }

        let members = recipient.members_resolved;
        txn.rcpt_to = members;
    }

    onRcpt (next, connection, params) {
        const plugin = this.plugin;

        // verify if we got a transaction
        const txn = connection.transaction;
        if (!txn) {
            return next();
        }

        // in case there's more than one recipient, log an error
        if (txn.rcpt_to.length > 1) {
            connection.logerror(plugin, 'Received more than one recipient!');
            return next();
        }

        const rcpt = txn.rcpt_to[txn.rcpt_to.length - 1];

        // check if we got a host part
        if (!rcpt.host) {
            txn.results.add(plugin, { fail: '!domain' });
            return next();
        }

        if (!this.is_loaded) {
            connection.logerror(plugin, 'Not loaded yet');
            return next(DENYSOFT, 'Backend failure. Please retry later.');
        }

        const plain_rcpt = rcpt.address().toLowerCase();

        // check if we can receive the mentioned email
        if (plain_rcpt in this.lookup_table) {
            txn.results.add(plugin, { recipients: [ this.lookup_table[plain_rcpt] ] });
            next(OK);
        } else {
            next();
        }
    }
}


module.exports = DistributionListPlugin;