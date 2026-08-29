'use strict';

const disabledMessage = 'Report execution is disabled. Enabling database-stored JavaScript requires reports.enabled=true and reports.unsafeJavaScriptExecution=true.';
const warningMessage = 'SECURITY WARNING: UNSAFE JAVASCRIPT REPORT EXECUTION IS ENABLED. Node vm is not a security boundary; use only with fully trusted report authors and database writers.';

function isReportExecutionEnabled(reportsConfig) {
    return Boolean(reportsConfig && reportsConfig.enabled === true && reportsConfig.unsafeJavaScriptExecution === true);
}

function assertReportExecutionEnabled(reportsConfig) {
    if (!isReportExecutionEnabled(reportsConfig)) {
        throw new Error(disabledMessage);
    }
}

function warnIfUnsafeReportExecutionEnabled(reportsConfig, warn) {
    if (isReportExecutionEnabled(reportsConfig)) {
        warn(warningMessage);
    }
}

module.exports = {
    assertReportExecutionEnabled,
    disabledMessage,
    isReportExecutionEnabled,
    warnIfUnsafeReportExecutionEnabled,
    warningMessage
};
