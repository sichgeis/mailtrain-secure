'use strict';

const REDACTED = '[REDACTED]';

function redactLogMessage(value, {redactFirstPathSegment = false} = {}) {
    let message = String(value === undefined || value === null ? '' : value);
    message = message.replace(/\b(authorization\s*:\s*(?:Bearer|Basic))\s+[^\s,]+/gi, `$1 ${REDACTED}`);
    message = message.replace(/\b(access-token\s*:)\s*[^\s,]+/gi, `$1 ${REDACTED}`);
    message = message.replace(/([?&\s](?:access_token|api_token|resetToken|reset_token|password|token)=)[^&\s]*/gi, `$1${REDACTED}`);
    message = message.replace(/([?&\s](?:email|usernameOrEmail)=)[^&\s]*/gi, `$1${REDACTED}`);
    message = message.replace(/(["']?(?:authorization|access_token|api_token|resetToken|reset_token|password|token|email|usernameOrEmail)["']?\s*:\s*)["']?[^,"'}\s]+["']?/gi, `$1${REDACTED}`);
    message = message.replace(/(\/login\/reset\/)[^/?\s]+\/[^/?\s]+/gi, `$1${REDACTED}/${REDACTED}`);
    if (redactFirstPathSegment) {
        message = message.replace(/((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)\/[^/?\s]+/i, `$1/${REDACTED}`);
    }
    message = message.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, REDACTED);
    message = message.replace(/\b[A-Z0-9._+-]+%40[A-Z0-9.-]+(?:\.[A-Z]{2,})?\b/gi, REDACTED);
    return message;
}

module.exports = {
    REDACTED,
    redactLogMessage
};
