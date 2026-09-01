'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {cloneTableColumns} = require('../src/lib/table-columns');

test('each table owns independent column definitions', () => {
    const render = value => value;
    const sharedColumns = [
        {data: 1, title: 'Name'},
        {data: 2, title: 'ID', render}
    ];

    const firstTableColumns = cloneTableColumns(sharedColumns);
    firstTableColumns[0].title = '<div>Name</div>';
    firstTableColumns[1].render = () => '<div>rendered</div>';

    const secondTableColumns = cloneTableColumns(sharedColumns);
    assert.notStrictEqual(firstTableColumns[0], sharedColumns[0]);
    assert.equal(sharedColumns[0].title, 'Name');
    assert.equal(sharedColumns[1].render, render);
    assert.equal(secondTableColumns[0].title, 'Name');
    assert.equal(secondTableColumns[1].render, render);
});
