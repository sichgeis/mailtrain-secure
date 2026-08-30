'use strict';

const router = require('../lib/router-async').create();
const {fetch: outboundFetch} = require('../lib/outbound-fetch');
const {webhookRateLimiters} = require('../lib/request-rate-limiters');
const campaigns = require('../models/campaigns');
const sendConfigurations = require('../models/send-configurations');
const contextHelpers = require('../lib/context-helpers');
const {CampaignMessageStatus} = require('../../shared/campaigns');
const {MailerType} = require('../../shared/send-configurations');
const log = require('../lib/log');
const config = require('../lib/config');
const builtinZoneMta = require('../lib/builtin-zone-mta');
const knex = require('../lib/knex');
const {WebhookDeliveryLedger} = require('../lib/webhook-delivery-ledger');
const {createMailgunUpload, mailgunFields} = require('../lib/mailgun-upload');
const {
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
const deliveryLedger = new WebhookDeliveryLedger({
    knex,
    leaseMs: webhookConfig.processingLeaseMs,
    retentionMs: webhookConfig.deliveryRetentionMs
});
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

async function runReplayProtected(reservation, handler) {
    return reservation ? reservation.run(handler) : handler();
}

async function fetchAwsCertificate(uri) {
    if (awsCertificates.has(uri)) {
        return awsCertificates.get(uri);
    }
    const response = await outboundFetch(uri, {
        method: 'GET',
        timeoutMs: webhookConfig.aws.certificateTimeoutMs,
        maxRedirects: 0,
        maxResponseSize: 65536,
        headers: {accept: 'application/x-pem-file,text/plain'}
    });
    if (response.statusCode !== 200) {
        const error = new Error('AWS SNS signing certificate request failed');
        error.status = 400;
        throw error;
    }
    const certificate = response.body;
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


router.postAsync('/aws', webhookRateLimiters.aws, async (req, res) => {
    assertProviderEnabled(webhookConfig.aws);
    req.body = parseJsonBody(req.body);

    await verifyAwsSnsMessage(req.body, {
        topicArns: webhookConfig.aws.topicArns,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        maxDeliveryAgeMs: webhookConfig.maxDeliveryAgeMs,
        fetchCertificate: fetchAwsCertificate
    });
    const replayReservation = await deliveryLedger.reserve('aws', req.body.MessageId);

    await runReplayProtected(replayReservation, async () => {
        switch (req.body.Type) {

            case 'SubscriptionConfirmation':
                if (req.body.SubscribeURL) {
                    await confirmAwsSnsSubscription(req.body, {
                        request: async options => {
                            const response = await outboundFetch(options.uri, {
                                method: options.method,
                                timeoutMs: options.timeout,
                                maxRedirects: 0,
                                maxResponseSize: 65536
                            });
                            if (response.statusCode < 200 || response.statusCode >= 300) {
                                const error = new Error('AWS SNS subscription confirmation request failed');
                                error.status = 400;
                                throw error;
                            }
                            return response;
                        },
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
                                    log.verbose('AWS', 'Marked an authenticated provider event as bounced');
                                    break;

                                case 'Complaint':
                                    if (req.body.Message.complaint) {
                                        await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                                        log.verbose('AWS', 'Marked an authenticated provider event as complaint');
                                    }
                                    break;
                            }
                        }
                    }
                }
                break;
        }
    });

    res.json({
        success: true
    });
});


router.postAsync('/sparkpost', webhookRateLimiters.sparkpost, async (req, res) => {
    assertProviderEnabled(webhookConfig.sparkpost);
    assertBasicAuthorization(req.get('authorization'), webhookConfig.sparkpost);
    const batchId = req.get('x-messagesystems-batch-id');
    if (!batchId) {
        const error = new Error('SparkPost batch id is missing');
        error.status = 400;
        throw error;
    }
    const replayReservation = await deliveryLedger.reserve('sparkpost', batchId);
    const events = [].concat(req.body || []); // This is just a cryptic way getting an array regardless whether req.body is empty, one item, or array

    await runReplayProtected(replayReservation, async () => {
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

            log.verbose('Sparkpost', 'Received authenticated event type "%s"', evt.type);

            const message = await campaigns.getMessageByCid(evt.campaign_id);
            if (!message) {
                continue;
            }

            switch (evt.type) {
                case 'bounce':
                // https://support.sparkpost.com/customer/portal/articles/1929896
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, [1, 10, 25, 30, 50].indexOf(Number(evt.bounce_class)) >= 0);
                    log.verbose('Sparkpost', 'Marked an authenticated provider event as bounced');
                    break;

                case 'spam_complaint':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                    log.verbose('Sparkpost', 'Marked an authenticated provider event as complaint');
                    break;

                case 'link_unsubscribe':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                    log.verbose('Sparkpost', 'Marked an authenticated provider event as unsubscribed');
                    break;
            }
        }
    });

    return res.json({
        success: true
    });
});


router.postAsync('/sendgrid', webhookRateLimiters.sendgrid, async (req, res) => {
    assertProviderEnabled(webhookConfig.sendgrid);
    const sendgridSignature = req.get('x-twilio-email-event-webhook-signature');
    verifySendGridSignature({
        rawBody: req.rawBody,
        timestamp: req.get('x-twilio-email-event-webhook-timestamp'),
        signature: sendgridSignature
    }, {
        publicKey: webhookConfig.sendgrid.publicKey,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        maxDeliveryAgeMs: webhookConfig.maxDeliveryAgeMs
    });
    let events = [].concat(req.body || []);

    for (const evt of events) {
        if (!evt) {
            continue;
        }
        if (typeof evt.sg_event_id !== 'string' || !evt.sg_event_id || evt.sg_event_id.length > 255) {
            const error = new Error('SendGrid event id is missing or invalid');
            error.status = 400;
            throw error;
        }
        const replayReservation = await deliveryLedger.reserve('sendgrid-event', evt.sg_event_id);
        await runReplayProtected(replayReservation, async () => {

            log.verbose('Sendgrid', 'Received authenticated event type "%s"', evt.event);

            const message = await campaigns.getMessageByCid(evt.campaign_id);
            if (!message) {
                return;
            }

            switch (evt.event) {
                case 'bounce':
                    // https://support.sparkpost.com/customer/portal/articles/1929896
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                    log.verbose('Sendgrid', 'Marked an authenticated provider event as bounced');
                    break;

                case 'spamreport':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                    log.verbose('Sendgrid', 'Marked an authenticated provider event as complaint');
                    break;

                case 'group_unsubscribe':
                case 'unsubscribe':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                    log.verbose('Sendgrid', 'Marked an authenticated provider event as unsubscribed');
                    break;
            }
        });
    }

    return res.json({
        success: true
    });
});


router.postAsync('/mailgun', webhookRateLimiters.mailgun, requireProvider(webhookConfig.mailgun), mailgunUpload, async (req, res) => {
    assertExpectedFields(req.body, mailgunFields);
    verifyMailgunSignature(req.body, {
        signingKey: webhookConfig.mailgun.signingKey,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        maxDeliveryAgeMs: webhookConfig.maxDeliveryAgeMs
    });
    const replayReservation = await deliveryLedger.reserve('mailgun', [].concat(req.body.token || []).shift());
    const evt = req.body;

    log.verbose('Mailgun', 'Received authenticated event type "%s"', evt.event);

    await runReplayProtected(replayReservation, async () => {
        const message = await campaigns.getMessageByCid([].concat(evt && evt.campaign_id || []).shift());
        if (message) {
            switch (evt.event) {
                case 'bounced':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                    log.verbose('Mailgun', 'Marked an authenticated provider event as bounced');
                    break;

                case 'complained':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.COMPLAINED, true);
                    log.verbose('Mailgun', 'Marked an authenticated provider event as complaint');
                    break;

                case 'unsubscribed':
                    await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.UNSUBSCRIBED, true);
                    log.verbose('Mailgun', 'Marked an authenticated provider event as unsubscribed');
                    break;
            }
        }
    });

    return res.json({
        success: true
    });
});


router.postAsync('/zone-mta', webhookRateLimiters.zoneMta, async (req, res) => {
    const zoneMtaToken = webhookConfig.zoneMta.token || (config.builtinZoneMTA.enabled ? builtinZoneMta.getPassword() : null);
    if (!config.builtinZoneMTA.enabled) {
        assertProviderEnabled(webhookConfig.zoneMta);
    }
    assertBearerAuthorization(req.get('authorization'), zoneMtaToken);
    req.body = parseJsonBody(req.body);

    if (req.body.id) {
        const replayReservation = await deliveryLedger.reserve('zone-mta', req.body.id);
        await runReplayProtected(replayReservation, async () => {
            const message = await campaigns.getMessageByResponseId(req.body.id);

            if (message) {
                await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                log.verbose('ZoneMTA', 'Marked an authenticated provider event as bounced');
            }
        });
    }

    res.json({
        success: true
    });
});


router.postAsync('/zone-mta/sender-config/:sendConfigurationCid', webhookRateLimiters.zoneMta, async (req, res) => {
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


router.postAsync('/postal', webhookRateLimiters.postal, async (req, res) => {
    assertProviderEnabled(webhookConfig.postal);
    req.body = parseJsonBody(req.body);
    const postalSignature = req.get('x-postal-signature-256');
    verifyPostalSignature({
        rawBody: req.rawBody,
        signature: postalSignature,
        keyId: req.get('x-postal-signature-kid'),
        timestamp: req.body.timestamp
    }, {
        publicKey: webhookConfig.postal.publicKey,
        keyIds: webhookConfig.postal.keyIds,
        maxClockSkewMs: webhookConfig.maxClockSkewMs,
        maxDeliveryAgeMs: webhookConfig.maxDeliveryAgeMs
    });
    const replayReservation = await deliveryLedger.reserve('postal', postalSignature);

    await runReplayProtected(replayReservation, async () => {
        switch (req.body.event) {

            case 'MessageDeliveryFailed':
                if (req.body.payload.message && req.body.payload.message.message_id) {
                    const message = await campaigns.getMessageByResponseId(req.body.payload.message.message_id);
                    if (message) {
                        await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, req.body.payload.status === 'HardFail');
                        log.verbose('Postal', 'Marked an authenticated provider event as bounced');
                    }
                }
                break;

            case 'MessageBounced':
                if (req.body.payload.original_message && req.body.payload.original_message.message_id) {
                    const message = await campaigns.getMessageByResponseId(req.body.payload.original_message.message_id);
                    if (message) {
                        await campaigns.changeStatusByMessage(contextHelpers.getAdminContext(), message, CampaignMessageStatus.BOUNCED, true);
                        log.verbose('Postal', 'Marked an authenticated provider event as bounced');
                    }
                }
                break;
        }
    });

    res.json({
        success: true
    });
});

module.exports = router;
