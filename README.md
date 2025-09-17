# django-db-rls
Django Row-Level Security

 - Utility `set_config()` to securely set parameter inside transaction only
 - Meta customisation & migration operations to manage RLS DDL
 - Middleware to encompass request-response cyle in atomic (similar to `ATOMIC_REQUESTS` but covering template response
   rendering)
 - Middleware to only wrap template response in atomic
 - System check that throws critical if using SUPERUSER
 - System check that throws critical if model with db_rls = True does not have RLS enabled (if disabled accidentally)
 - Management command to initialise an unprivileged role

TODO:

 - Management command to list models by RLS managed along with policies, then non-RLS models
   - Same command to raise error if out of sync with DB
   - make use of `SELECT row_security_active('table_name');`
 - Doc examples and how to setup DATABASES
 - Alias setup with --databases=superuser for migrate
 - Add note about CREATE EXTENSION may require a SUPERUSER extension unless trusted?
 - Provide an option for prefixing commands with set_config similar to pgtrigger?
 - AtomicRequestsMiddleware - figure out how to skip views
 - Warning though: Having the webapp user create the tables makes them the owner, and they have the privilege of
   disabling row level security, which makes force moot if an attacker has ability to commit sql injection.
 - Add some sort of warning to let users know that a separate role for creating tables is better
 - Add note bout Atomic Middleware or some mixin covering dispatch or be selective + template response middleware
 - Add note that when using 2 connections that RunPython operations must be using the correct, supplied alias
 - Add a check to make sure policies are in sync
 - Supply a policy for "is_superuser" check
 - Improve naming of operations: include model name
 - Add ability to set default_policies on a default meta?
