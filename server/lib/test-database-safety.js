'use strict';

const CONSENT = 'YES_I_AM_USING_SYNTHETIC_DATA';
const SYSTEM_DATABASES = new Set(['information_schema', 'mysql', 'performance_schema', 'sys']);

function assertSafeTestDatabase({environment, database, allowDestructiveTests}) {
    if (environment !== 'test') {
        throw new Error('Destructive database tests require NODE_ENV=test');
    }

    if (allowDestructiveTests !== CONSENT) {
        throw new Error(`Destructive database tests require explicit synthetic data consent: ${CONSENT}`);
    }

    const normalized = String(database || '').trim().toLowerCase();
    const clearlyIsolated = /(?:^|[_-])(test|ci)(?:$|[_-])/.test(normalized);
    const looksProductionLike = !normalized || normalized === 'mailtrain' || normalized.includes('prod') || normalized === 'production';

    if (!clearlyIsolated || looksProductionLike || SYSTEM_DATABASES.has(normalized)) {
        throw new Error(`Refusing destructive operation: "${database || ''}" is not an isolated test database`);
    }
}

module.exports = {
    CONSENT,
    assertSafeTestDatabase
};
