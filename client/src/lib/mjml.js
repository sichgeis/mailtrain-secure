'use strict';

import {isArray, mergeWith} from 'lodash';
import mjml2html, {BodyComponent, HeadComponent} from "mjml-core";
import presetCore from "mjml-preset-core";

export { BodyComponent, HeadComponent };

export class MJML {
    constructor() {
        this.components = [...presetCore.components];
        this.dependencies = {...presetCore.dependencies};
        this.headRaw = [];
    }

    registerDependencies(dep) {
        function mergeArrays(objValue, srcValue) {
            if (isArray(objValue) && isArray(srcValue)) {
                return objValue.concat(srcValue)
            }
        }

        mergeWith(this.dependencies, dep, mergeArrays);
    }

    registerComponent(Component) {
        this.components.push(Component);
    }

    addToHeader(src) {
        this.headRaw.push(src);
    }

    mjml2html(mjml) {
        const res = mjml2html(mjml, {
            presets: [{
                components: this.components,
                dependencies: this.dependencies
            }]
        });

        if (this.headRaw.length > 0 && res && typeof res.html === 'string') {
            res.html = res.html.replace('</head>', `${this.headRaw.join('\n')}\n</head>`);
        }

        return res;
    }
}

const mjmlInstance = new MJML();

export default function defaultMjml2html(src) {
    return mjmlInstance.mjml2html(src);
}
