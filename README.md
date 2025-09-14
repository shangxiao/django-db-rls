# django-db-rls
Django Row-Level Security

 - Utility `set_config()` to securely set parameter inside transaction only
 - Meta customisation & migration operations to manage RLS DDL
 - Middleware to encompass request-response cyle in atomic (similar to `ATOMIC_REQUESTS` but covering template response
   rendering)
 - Middleware to only wrap template response in atomic

TODO:

 - Management command to list models by RLS managed along with policies, then non-RLS models
   - Same command to raise error if out of sync with DB
 - Possible system check
 - Utility to raise error/warning? if the default DB connection has superuser privileges
 - Script (not migration) that will initialise an "webapp" or "rls" role and setup the proper grants
 - Doc examples and how to setup DATABASES
 - Alias setup with --databases=superuser for migrate
 - Add note about CREATE EXTENSION may require a SUPERUSER extension unless trusted?
