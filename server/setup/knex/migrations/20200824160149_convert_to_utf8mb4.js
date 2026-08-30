
exports.up = function(knex) {
  return knex.raw('SELECT table_name AS tableName FROM information_schema.tables WHERE table_schema = ?', [knex.client.database()])
    .then(function(result) {
       return result[0].reduce((chain, table) => chain.then(() => knex.raw(
         'ALTER TABLE ?? CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci',
         [table.tableName]
       )), Promise.resolve());
    });
};

exports.down = function(knex, Promise) {
  
};
