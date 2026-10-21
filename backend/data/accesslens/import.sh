#!/usr/bin/env bash
# Usage: ./import.sh "mongodb://localhost:27017" accesslens
URI=${1:-mongodb://localhost:27017}; DB=${2:-accesslens}
cd "$(dirname "$0")"
for f in admin_roles app_usage apps assignments cohorts config expected_findings expected_findings_github findings github_org_members github_repos github_scim_identities github_teams group_members groups okta_admin_roles okta_app_assignments okta_apps okta_groups okta_sso_last_seen okta_users tenants user_cohorts users; do
  mongoimport --uri "$URI" --db "$DB" --collection "$f" --drop --jsonArray --file "$f.json"
done
mongosh "$URI/$DB" --eval 'db.createCollection("decisions")' >/dev/null 2>&1
mongosh "$URI/$DB" indexes.js
