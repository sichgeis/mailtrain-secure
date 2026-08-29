'use strict';

const router = require('../lib/router-async').create();
const messageSender = require('../lib/message-sender');
const {untrustedContentSecurityPolicy} = require('../lib/browser-security');
const {sanitizeUntrustedHtml} = require('../lib/html-sanitizer');


router.get('/:campaign/:list/:subscription', (req, res, next) => {
    messageSender.getMessage(req.params.campaign, req.params.list, req.params.subscription)
        .then(result => {
            const html = sanitizeUntrustedHtml(result.html);
            res.setHeader('Content-Security-Policy', untrustedContentSecurityPolicy());

            if (html.match(/<\/body\b/i)) {
                res.render('archive/view', {
                    layout: 'archive/layout-raw',
                    message: html
                });
            } else {
                res.render('archive/view', {
                    layout: 'archive/layout-wrapped',
                    message: html
                });
            }

        })
        .catch(err => next(err));
});

module.exports = router;
