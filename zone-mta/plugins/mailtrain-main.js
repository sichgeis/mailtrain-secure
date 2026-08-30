'use strict';

// Set module title
module.exports.title = 'Mailtrain integration (main)';

// Initialize the module
module.exports.init = (app, done) => {

    app.addHook('queue:bounce', (bounce, maildrop, next) => {
        if (!app.config.bounceUrl || !app.config.bounceToken) {
            app.logger.error('MailtrainBounce', 'Authenticated Mailtrain bounce callback is not configured');
            return next();
        }

        let retries = 0;
        const body = {
            id: bounce.id,
            to: bounce.to,
            seq: bounce.seq,
            returnPath: bounce.from,
            category: bounce.category,
            time: bounce.time,
            response: bounce.response
        };
        const fbl = bounce.headers.getFirst('X-FBL');
        if (fbl) {
            body.fbl = fbl;
        }

        const notifyBounce = () => {
            let returned = false;
            const stream = require('nodemailer/lib/fetch')(app.config.bounceUrl, {
                body,
                headers: {
                    Authorization: `Bearer ${app.config.bounceToken}`
                }
            });

            stream.on('readable', () => {
                while (stream.read() !== null) {
                    // Drain the response so the connection can close.
                }
            });
            stream.once('error', err => {
                if (returned) return;
                returned = true;
                app.logger.error('MailtrainBounce', err.message);
                if (retries++ <= 5) {
                    setTimeout(notifyBounce, Math.pow(retries, 2) * 1000).unref();
                } else {
                    next();
                }
            });
            stream.on('end', () => {
                if (returned) return;
                returned = true;
                next();
            });
        };

        setImmediate(notifyBounce);
    });

    process.send({
        type: 'zone-mta-started'
    });

    process.on('message', msg => {
        if (msg === 'exit') {
            process.exit();        }
    });

    done();
};
