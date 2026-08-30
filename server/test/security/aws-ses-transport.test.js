'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { SendEmailCommand } = require('@aws-sdk/client-sesv2');
const nodemailer = require('nodemailer');

const { createSesBinding } = require('../../lib/aws-ses-transport');

test('Nodemailer sends through the AWS SDK v3 SES command interface', async () => {
    let sentCommand;
    const sesClient = {
        config: { region: async () => 'eu-central-1' },
        async send(command) {
            sentCommand = command;
            return { MessageId: 'synthetic-message-id' };
        }
    };
    const transport = nodemailer.createTransport({
        SES: createSesBinding({ region: 'eu-central-1' }, sesClient)
    });

    const info = await transport.sendMail({
        from: 'sender@example.test',
        to: 'recipient@example.test',
        subject: 'SES compatibility regression',
        text: 'Synthetic message'
    });

    assert.equal(sentCommand instanceof SendEmailCommand, true);
    assert.equal(sentCommand.input.FromEmailAddress, 'sender@example.test');
    assert.deepEqual(sentCommand.input.Destination.ToAddresses, ['recipient@example.test']);
    assert.match(info.messageId, /synthetic-message-id@eu-central-1\.amazonses\.com/);
});
