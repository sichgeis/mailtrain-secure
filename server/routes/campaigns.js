'use strict';

const passport = require('../lib/passport');
const routerFactory = require('../lib/router-async');
const campaigns = require('../models/campaigns');
const lists = require('../models/lists');
const users = require('../models/users');
const contextHelpers = require('../lib/context-helpers');
const { AppType } = require('../../shared/app');
const {untrustedContentSecurityPolicy} = require('../lib/browser-security');
const {sanitizeUntrustedHtml} = require('../lib/html-sanitizer');


users.registerRestrictedAccessTokenMethod('rssPreview', async ({campaignCid, listCid}) => {

    const campaign = await campaigns.getByCid(contextHelpers.getAdminContext(), campaignCid);
    const list = await lists.getByCid(contextHelpers.getAdminContext(), listCid);

    return {
        permissions: {
            'campaign': {
                [campaign.id]: new Set(['view'])
            },
            'list': {
                [list.id]: new Set(['view', 'viewTestSubscriptions'])
            }
        }
    };
});

async function getRouter(appType) {
    const router = routerFactory.create();

    if (appType === AppType.SANDBOXED) {

        router.get('/rss-preview/:campaign/:list/:subscription', passport.loggedIn, (req, res, next) => {
            campaigns.getRssPreview(req.context, req.params.campaign, req.params.list, req.params.subscription)
                .then(result => {
                    const html = sanitizeUntrustedHtml(result.html);
                    res.setHeader('Content-Security-Policy', untrustedContentSecurityPolicy({frameAncestor: getTrustedUrl()}));

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
    }

    return router;
}

module.exports.getRouter = getRouter;
