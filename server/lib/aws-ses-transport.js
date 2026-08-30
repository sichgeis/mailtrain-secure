'use strict';

const { SESv2Client, SendEmailCommand } = require('@aws-sdk/client-sesv2');

function createSesBinding(settings, clientOverride) {
    const sesClient = clientOverride || new SESv2Client({
        region: settings.region,
        credentials: {
            accessKeyId: settings.key,
            secretAccessKey: settings.secret
        }
    });

    return { sesClient, SendEmailCommand };
}

module.exports = { createSesBinding };
