// mongosh accesslens indexes.js
db.users.createIndex({tenant_id:1,okta_id:1},{unique:true});
db.users.createIndex({manager_id:1});
db.users.createIndex({status:1});
db.assignments.createIndex({user_id:1,app_id:1});
db.assignments.createIndex({app_id:1});
db.group_members.createIndex({group_id:1,user_id:1},{unique:true});
db.app_usage.createIndex({user_id:1,app_id:1},{unique:true});
db.user_cohorts.createIndex({user_id:1});
db.user_cohorts.createIndex({cohort_id:1});
db.findings.createIndex({user_id:1});
db.findings.createIndex({rule:1,risk_score:-1});
db.findings.createIndex({status:1});
db.admin_roles.createIndex({user_id:1});
db.okta_app_assignments.createIndex({externalId:1});
db.github_scim_identities.createIndex({externalId:1});
