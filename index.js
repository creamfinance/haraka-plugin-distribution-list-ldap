const DistributionListPlugin = require('./distributionlistplugin.js');

let dlp;

exports.register = function () {
	console.log('Called Register!');
    dlp = new DistributionListPlugin(this, require);

    dlp.register();
}
