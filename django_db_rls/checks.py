from django.apps import apps
from django.core.checks import Critical, Error
from django.db import connection


def check_no_superuser(app_configs, **kwargs):
    errors = []
    # specifically check the default connection
    with connection.cursor() as cursor:
        cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        if cursor.fetchone()[0]:
            errors.append(
                Error(
                    "The default database has SUPERUSER privilege. Row-level security does NOT apply to SUPERUSER roles.",
                    hint="Create a new role without SUPERUSER.",
                    id="django_db_rls.E001",
                )
            )
    return errors


def check_rls_tables_are_secure(app_configs, **kwargs):
    errors = []

    if app_configs:
        models = [
            model for app_config in app_configs for model in app_config.get_models()
        ]
    else:
        models = apps.get_models()

    with connection.cursor() as cursor:
        for model in models:
            if not getattr(model._meta, "db_rls", False):
                continue

            table_name = model._meta.db_table
            cursor.execute("SELECT row_security_active(%s);", [table_name])
            (rls_active,) = cursor.fetchone()

            if not rls_active:
                errors.append(
                    Critical(
                        f"Row-level security is NOT active for table '{table_name}'.",
                        obj=model,
                        id="django_db_rls.C001",
                    )
                )

    return errors
