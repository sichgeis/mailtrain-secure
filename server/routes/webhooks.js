'use strict';

const router = require('../lib/router-async').create();
const request = require('request-promise');
const campaigns = require('../models/campaigns');
const sendConfigurations = require('../models/send-configurations');
const contextHelpers = require('../lib/context-helpers');
const {CampaignMessageStatus} = require('../../shared/campaigns');
const {MailerType} = require('../../shared/send-configurations');
const log = require('../lib/log');
const config = require('../lib/config');
const builtinZoneMta = require('../lib/builtin-zone-mta');
const {createMailgunUpload, mailgunFields} = require('../lib/mailgun-upload');
const {
    ReplayCache,
    assertBasicAuthorization,
    assertBearerAuthorization,
    assertExpectedFields,
    confirmAwsSnsSubscription,
    verifyAwsSnsMessage,
    verifyMailgunSignature,
    verifyPostalSignature,
    verifySendGridSignature
} = require('../lib/webhook-security');

const webhookConfig = config.security.webhooks;
const replayOptions = {maxEntries: webhookConfig.replayCacheEntries};
const awsReplayCache = new ReplayCache(replayOptions);
const sparkpostReplayCache = new ReplayCache(replayOptions);
const sendgridReplayCache = new ReplayCache(replayOptions);
const mailgunReplayCache = new ReplayCache(replayOptions);
const postalReplayCache = new ReplayCache(replayOptions);
const zoneMtaReplayCache = new ReplayCache(replayOptions);
const awsCertificates = new Map();
const mailgunUpload = createMailgunUpload(webhookConfig.mailgun);

function assertProviderEnabled(provider) {
    if (!provider || provider.enabled !== true) {
        const error = new Error('Webhook provider is disabled');
        error.status = 404;
        throw error;
    }
}

function requireProvider(provider) {
    return (req, res, next) => {
        try {
            assertProviderEnabled(provider);
            next();
        } catch (err) {
            next(err);
        }
    };
}

function parseJsonBody(body) {
    if (typeof body !== 'string') {
        return body;
    }
    try {
        return JSON.parse(body);
    } catch (err) {
        err.status = 400;
        throw err;
    }
}

async function fetchAwsCertificate(uri) {
    if (awsCertificates.has(uri)) {
        return awsCertificates.get(uri);
    }
    const certificate = await request({
        uri,
        method: 'GET',
        timeout: webhookConfig.aws.certificateTimeoutMs,
        followRedirect: false,
        simple: true
    });
    if (Buffer.byteLength(certificate) > 65536) {
        const error = new Error('AWS SNS signing certificate is oversized');
        error.status = 400;
        throw error;
    }
    if (awsCertificates.size >= 8) {
        awsCertificates.delete(awsCertificates.keys().next().value);
    }
    awsCertificates.set(uri, certificate);
    return certificate;
}


router.postAsync('/aws', async (req, res) => {
    assertProviderEnabled(webhookConfig.aws);
    req.body = parseJsonBody(req.body);

    await verifyAwsSnsMessage(req.body, {
        topicArns: webhookConfig.aws.topicArns,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        replayCache: awsReplayCache,
        fetchCertificate: fetchAwsCertificate
    });

    switch (req.body.Type) {

        case 'SubscriptionConfirmation':
            if (req.body.SubscribeURL) {
                await confirmAwsSnsSubscription(req.body, {
                    request,
                    timeout: webhookConfig.aws.confirmationTimeoutMs
                });
                break;
            } else {
                const err = new Error('SubscribeURL not set');
                err.status = 400;
                throw err;
            }

        case 'Notification':
            if (req.body.Message) {
                req.body.Message = parseJsonBody(req.body.Message);

                if (req.body.Message.mail && req.body.Message.mail.messageId) {
                    const message = await campaigns.getMessageByResponseId(req.body.Message.mail.messageId);

                    if (message) {
                        switch (req.body.Message.notificationType) {
                            case 'Bounce':
                                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, req.body.Message.bounce.bounceType === 'Permanent');
                                log.verbose('AWS', 'Marked message %s as bounced', req.body.Message.mail.messageId);
                                break;

                            case 'Complaint':
                                if (req.body.Message.complaint) {
                                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                                    log.verbose('AWS', 'Marked message %s as complaint', req.body.Message.mail.messageId);
                                }
                                break;
                        }
                    }
                }
            }
            break;
    }

    res.json({
        success: true
    });
});


router.postAsync('/sparkpost', async (req, res) => {
    assertProviderEnabled(webhookConfig.sparkpost);
    assertBasicAuthorization(req.get('authorization'), webhookConfig.sparkpost);
    const batchId = req.get('x-messagesystems-batch-id');
    if (!batchId) {
        const error = new Error('SparkPost batch id is missing');
        error.status = 400;
        throw error;
    }
    sparkpostReplayCache.assertUnused(`sparkpost:${batchId}`, webhookConfig.maxClockSkewMs);
    const events = [].concat(req.body || []); // This is just a cryptic way getting an array regardless whether req.body is empty, one item, or array

    for (const curEvent of events) {
        let msys = curEvent && curEvent.msys;
        let evt;

        if (msys && msys.message_event) {
            evt = msys.message_event;
        } else if (msys && msys.unsubscribe_event) {
            evt = msys.unsubscribe_event;
        } else {
            continue;
        }

        log.verbose('Sendgrid', 'Received issue "%s" for message id "%s"', evt.type, evt.campaign_id);

        const message = await campaigns.getMessageByCid(evt.campaign_id);
        if (!message) {
            continue;
        }

        switch (evt.type) {
            case 'bounce':
                // https://support.sparkpost.com/customer/portal/articles/1929896
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, [1, 10, 25, 30, 50].indexOf(Number(evt.bounce_class)) >= 0);
                log.verbose('Sparkpost', 'Marked message %s as bounced', evt.campaign_id);
                break;

            case 'spam_complaint':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                log.verbose('Sparkpost', 'Marked message %s as complaint', evt.campaign_id);
                break;

            case 'link_unsubscribe':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                log.verbose('Sparkpost', 'Marked message %s as unsubscribed', evt.campaign_id);
                break;
        }
    }

    return res.json({
        success: true
    });
});


router.postAsync('/sendgrid', async (req, res) => {
    assertProviderEnabled(webhookConfig.sendgrid);
    verifySendGridSignature({
        rawBody: req.rawBody,
        timestamp: req.get('x-twilio-email-event-webhook-timestamp'),
        signature: req.get('x-twilio-email-event-webhook-signature')
    }, {
        publicKey: webhookConfig.sendgrid.publicKey,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        replayCache: sendgridReplayCache
    });
    let events = [].concat(req.body || []);

    for (const evt of events) {
        if (!evt) {
            continue;
        }

        log.verbose('Sendgrid', 'Received issue "%s" for message id "%s"', evt.event, evt.campaign_id);

        const message = await campaigns.getMessageByCid(evt.campaign_id);
        if (!message) {
            continue;
        }

        switch (evt.event) {
            case 'bounce':
                // https://support.sparkpost.com/customer/portal/articles/1929896
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                log.verbose('Sendgrid', 'Marked message %s as bounced', evt.campaign_id);
                break;

            case 'spamreport':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                log.verbose('Sendgrid', 'Marked message %s as complaint', evt.campaign_id);
                break;

            case 'group_unsubscribe':
            case 'unsubscribe':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                log.verbose('Sendgrid', 'Marked message %s as unsubscribed', evt.campaign_id);
                break;
        }
    }

    return res.json({
        success: true
    });
});


router.postAsync('/mailgun', requireProvider(webhookConfig.mailgun), mailgunUpload, async (req, res) => {
    assertExpectedFields(req.body, mailgunFields);
    verifyMailgunSignature(req.body, {
        signingKey: webhookConfig.mailgun.signingKey,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        replayCache: mailgunReplayCache
    });
    const evt = req.body;

    log.verbose('Mailgun', 'Received issue "%s" for message id "%s"', evt.event, evt.campaign_id);

    const message = await campaigns.getMessageByCid([].concat(evt && evt.campaign_id || []).shift());
    if (message) {
        switch (evt.event) {
            case 'bounced':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                log.verbose('Mailgun', 'Marked message %s as bounced', evt.campaign_id);
                break;

            case 'complained':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                log.verbose('Mailgun', 'Marked message %s as complaint', evt.campaign_id);
                break;

            case 'unsubscribed':
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                log.verbose('Mailgun', 'Marked message %s as unsubscribed', evt.campaign_id);
                break;
        }
    }

    return res.json({
        success: true
    });
});


router.postAsync('/zone-mta', async (req, res) => {
    const zoneMtaToken = webhookConfig.zoneMta.token || (config.builtinZoneMTA.enabled ? builtinZoneMta.getPassword() : null);
    if (!config.builtinZoneMTA.enabled) {
        assertProviderEnabled(webhookConfig.zoneMta);
    }
    assertBearerAuthorization(req.get('authorization'), zoneMtaToken);
    req.body = parseJsonBody(req.body);

    if (req.body.id) {
        zoneMtaReplayCache.assertUnused(`zone-mta:${req.body.id}`, webhookConfig.maxClockSkewMs);
        const message = await campaigns.getMessageByResponseId(req.body.id);

        if (message) {
            await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
            log.verbose('ZoneMTA', 'Marked message (campaign:%s, list:%s, subscription:%s) as bounced', message.campaign, message.list, message.subscription);
        }
    }

    res.json({
        success: true
    });
});


router.postAsync('/zone-mta/sender-config/:sendConfigurationCid', async (req, res) => {
    const sendConfiguration = await sendConfigurations.getByCid(contextHelpers.getAdminContext(), req.params.sendConfigurationCid, false, true);

    if (sendConfiguration.mailer_type !== MailerType.ZONE_MTA) {
        const error = new Error('Invalid ZoneMTA send configuration');
        error.status = 404;
        throw error;
    }
    assertBearerAuthorization(req.get('authorization'), sendConfiguration.mailer_settings.dkimApiKey);

    const dkimDomain = sendConfiguration.mailer_settings.dkimDomain;
    const dkimSelector = (sendConfiguration.mailer_settings.dkimSelector || '').trim();
    const dkimPrivateKey = (sendConfiguration.mailer_settings.dkimPrivateKey || '').trim();

    if (!dkimSelector || !dkimPrivateKey) {
        // empty response
        return res.json({});
    }

    const from = (req.body.from || '').trim();
    const domain = from.split('@').pop().toLowerCase().trim();

    res.json({
        dkim: {
            keys: [{
                domainName: dkimDomain || domain,
                keySelector: dkimSelector,
                privateKey: dkimPrivateKey
            }]
        }
    });
});


router.postAsync('/postal', async (req, res) => {
    assertProviderEnabled(webhookConfig.postal);
    req.body = parseJsonBody(req.body);
    verifyPostalSignature({
        rawBody: req.rawBody,
        signature: req.get('x-postal-signature-256'),
        keyId: req.get('x-postal-signature-kid'),
        timestamp: req.body.timestamp
    }, {
        publicKey: webhookConfig.postal.publicKey,
        keyIds: webhookConfig.postal.keyIds,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        replayCache: postalReplayCache
    });

    switch (req.body.event) {

        case 'MessageDeliveryFailed':
            if (req.body.payload.message && req.body.payload.message.message_id) {
                const message = await campaigns.getMessageByResponseId(req.body.payload.message.message_id);
                if (message) {
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, req.body.payload.status === 'HardFail');
                    log.verbose('Postal', 'Marked message %s as bounced', req.body.payload.message.message_id);
                }
            }
            break;

        case 'MessageBounced':
            if (req.body.payload.original_message && req.body.payload.original_message.message_id) {
                const message = await campaigns.getMessageByResponseId(req.body.payload.original_message.message_id);
                if (message) {
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                    log.verbose('Postal', 'Marked message %s as bounced', req.body.payload.original_message.message_id);
                }
            }
            break;
    }

    res.json({
        success: true
    });
});

module.exports = router;
