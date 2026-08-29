# Role-grant audit

Stage 2 enforces grant ceilings for all new and changed entity shares and privileged global-role assignments. Existing rows are preserved because historical share rows do not record who granted them, so Mailtrain cannot safely infer whether a past grant exceeded that person's authority.

Before deploying the authorization change, run this read-only inventory against a restored staging copy:

```sh
cd server
npm run security:audit-role-grants > role-grant-audit.json
```

The report contains numeric user/namespace identifiers and role names only; it excludes usernames, email addresses, credentials, and subscriber data. Review every explicit namespace share and every privilege-bearing global assignment. Correct inappropriate grants through an authorized administrator after taking a backup. The command never changes or deletes assignments.
