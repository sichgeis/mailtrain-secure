'use strict';

function cloneTableColumns(columns) {
    return columns.map(column => ({...column}));
}

module.exports = {cloneTableColumns};
