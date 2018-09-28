const ldap = require('ldapjs');
let Address;

class DistributionListPlugin {
    constructor (plugin, require) {
        this.plugin = plugin;
        Address = require('address-rfc2821').Address;
        this.outbound = require('outbound');
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
        let members = recipient.member;


        // Check if we got a distribution list, or a security list
        if (((recipient.groupType & 0x80000000) >>> 0) == 0x80000000) {
            connection.logdebug(plugin, 'Security Group, skipping');
            return next();
        }

        if (!(members instanceof Array)) {
            members = [ members ];
        }

        if (members.length > 0) {
            filter = '(|';

            for (var x = 0; x < members.length; x++) {
                filter += '(distinguishedName=' + members[x] + ')';
            }

            filter += ')'
        }

        connection.logdebug(plugin, 'Final search filter: ' + filter);

        var cfg = this.cfg.main;

        // Check if we can find a group (based on the filter), that has this email (based on the filter)
        let client;

        try {
            client = ldap.createClient({ url: cfg.server });
        } catch (e) {
            connection.logerror(plugin, 'connect error: ' + e);
            return next();
        }

        // Handle the login
        client.bind(cfg.binddn, cfg.bindpw, (err) => {
            if (err) {
                connection.logerror(plugin, 'Bind Error: ' + err);
                return next(DENYSOFT, 'Backend failure. Please retry later.');
            }

            client.search(
                cfg.basedn,
                { filter: filter, scope: 'sub', attributes: [ 'dn', 'mail' ] },
                (err, emitter) => {
                    if (err) {
                        connection.logerror(plugin, 'Queue/Search', err);
                        return next(DENYSOFT, 'Backend error. Please retry later.')
                    }

                    emitter.on('searchEntry', (entry) => {
                        connection.logdebug(plugin, 'Adding to rcpt ' + entry.object.mail);
                        final_rcpt.push(new Address(entry.object.mail));
                    });

                    emitter.on('error', (err) => {
                        connection.logerror(plugin, 'Queue/Search/Error', err);
                        next(DENYSOFT, 'Backend failure. Please retry later.')
                    });

                    emitter.on('end', (result) => {
                        txn.rcpt_to = final_rcpt;

                        next();
                    });
                }
            );
        });
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

        txn.results.add(plugin, { msg: 'connecting' });

        const domain = rcpt.host.toLowerCase();
        const cfg = this.cfg[domain] || this.cfg.main;

        if (!cfg || !cfg.binddn || !cfg.bindpw) {
            connection.logerror(plugin, 'no LDAP config found for ' + domain);
            return next();
        }

        // Check if we can find a group (based on the filter), that has this email (based on the filter)
        let client;

        try {
            client = ldap.createClient({ url: cfg.server });
        } catch (e) {
            connection.logerror(plugin, 'connect error: ' + e);
            return next();
        }

        client.on('error', (err) => {
            connection.logerror(plugin, 'Connection Error: ' + err);
            return next(DENYSOFT, 'Backend failure. Please retry later.');
        });

        // Handle the login
        client.bind(cfg.binddn, cfg.bindpw, (err) => {
            if (err) {
                connection.logerror(plugin, 'Bind Error: ' + err);
                return next(DENYSOFT, 'Backend failure. Please retry later.');
            }

            const options = this.getSearchOptions(cfg, rcpt);

            connection.logdebug(plugin, options);

            client.search(cfg.basedn, options, (err, emitter) => {
                if (err) {
                    connection.logerror(plugin, 'Rcpt/Search: ' + err);
                    return next(DENYSOFT, 'Backend failure. Please retry later.');
                }

                const items = [];

                emitter.on('searchEntry', (entry) => {
                    connection.logdebug(plugin, entry.object);
                    items.push(entry.object);
                });

                emitter.on('error', (err) => {
                    connection.logerror(plugin, 'Rcpt/Search/Error', err);
                    next(DENYSOFT, 'Backend failure. Please retry later.')
                });

                emitter.on('end', (result) => {

                    if (items.length == 1) {
                        txn.results.add(plugin, { recipients: items });

                        return next(OK);
                    }

                    if (items.length > 1) {
                        connection.logerror(plugin, 'Found multiple entries');
                        return next(DENYSOFT, 'Backend failure. Please retry later.');
                    }

                    // continue here, pass on to next plugin
                    next();
                });
            });
        });
    }

    getSearchOptions (cfg, rcpt) {
        const plain_rcpt = rcpt.address().toLowerCase();

        return {
            filter: cfg.filter.replace(/%u/g, plain_rcpt),
            scope: 'sub',
            attributes: ['dn','member','mail','proxyAddresses','groupType']
        };
    }
}


module.exports = DistributionListPlugin;