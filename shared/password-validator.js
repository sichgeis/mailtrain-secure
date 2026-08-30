'use strict';

function passwordValidator(t) {
    const config = {
        allowPassphrases: true,
        maxLength: 128,
        minLength: 10,
        minPhraseLength: 20,
        minOptionalTestsToPass: 4
    };

    if (t) {
        config.translate = {
            minLength: function (minLength) {
                return t('thePasswordMustBeAtLeastMinLength', { minLength });
            },
            maxLength: function (maxLength) {
                return t('thePasswordMustBeFewerThanMaxLength', { maxLength });
            },
            repeat: t('thePasswordMayNotContainSequencesOfThree'),
            lowercase: t('thePasswordMustContainAtLeastOne'),
            uppercase: t('thePasswordMustContainAtLeastOne-1'),
            number: t('thePasswordMustContainAtLeastOneNumber'),
            special: t('thePasswordMustContainAtLeastOneSpecial')
        }
    }

    const translate = config.translate || {
        minLength: minLength => `The password must be at least ${minLength} characters long.`,
        maxLength: maxLength => `The password must be fewer than ${maxLength} characters.`,
        repeat: 'The password may not contain sequences of three or more repeated characters.',
        lowercase: 'The password must contain at least one lowercase letter.',
        uppercase: 'The password must contain at least one uppercase letter.',
        number: 'The password must contain at least one number.',
        special: 'The password must contain at least one special character.'
    };

    return {
        test(password) {
            password = password || '';
            const requiredErrors = [
                password.length < config.minLength ? translate.minLength(config.minLength) : null,
                password.length > config.maxLength ? translate.maxLength(config.maxLength) : null,
                /(.)\1{2,}/.test(password) ? translate.repeat : null
            ];
            const optionalErrors = [
                /[a-z]/.test(password) ? null : translate.lowercase,
                /[A-Z]/.test(password) ? null : translate.uppercase,
                /[0-9]/.test(password) ? null : translate.number,
                /[^A-Za-z0-9]/.test(password) ? null : translate.special
            ];
            const isPassphrase = config.allowPassphrases && password.length >= config.minPhraseLength;
            const evaluatedErrors = isPassphrase ? requiredErrors : requiredErrors.concat(optionalErrors);
            const failedTests = [];
            const passedTests = [];

            evaluatedErrors.forEach((error, index) => (error ? failedTests : passedTests).push(index));
            const optionalTestsPassed = isPassphrase ? 0 : optionalErrors.filter(error => !error).length;
            const requiredTestErrors = requiredErrors.filter(Boolean);
            const optionalTestErrors = isPassphrase ? [] : optionalErrors.filter(Boolean);

            return {
                errors: requiredTestErrors.concat(optionalTestErrors),
                failedTests,
                passedTests,
                requiredTestErrors,
                optionalTestErrors,
                isPassphrase,
                strong: requiredTestErrors.length === 0 &&
                    (isPassphrase || optionalTestsPassed >= config.minOptionalTestsToPass),
                optionalTestsPassed
            };
        }
    };
}

module.exports = passwordValidator;
