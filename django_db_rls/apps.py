from django.apps import AppConfig
from django.db.migrations.autodetector import registry
from django.db.models.options import DEFAULT_NAMES
from django_db_rls.db_utils import AddPolicy, AlterPolicy, AlterRLS, RemovePolicy

DEFAULT_NAMES.update(["db_rls", "db_rls_policies"])


def rls_changes(
    app_label, model_name, from_state, to_state, from_model_state, to_model_state
):
    operations = []

    if (
        from_model_state.options.get("db_rls") if from_model_state else None
    ) != to_model_state.options.get("db_rls"):
        operations += [AlterRLS(model_name, to_model_state.options.get("db_rls"))]

    from_db_rls_policies = (
        from_model_state.options.get("db_rls_policies", []) if from_model_state else []
    )
    to_db_rls_policies = to_model_state.options.get("db_rls_policies", [])

    # compile before passing to operation to avoid complex objects from being serialized

    for policy in from_db_rls_policies:
        model = to_state.apps.get_model(app_label, model_name)
        policy.compile(model)

    for policy in to_db_rls_policies:
        model = to_state.apps.get_model(app_label, model_name)
        policy.compile(model)

    altered_policies = [
        policy
        for policy in to_db_rls_policies
        if policy not in from_db_rls_policies
        and policy.name in [from_policy.name for from_policy in from_db_rls_policies]
    ]
    new_policies = [
        policy
        for policy in to_db_rls_policies
        if policy not in from_db_rls_policies and policy not in altered_policies
    ]
    removed_policies = [
        policy
        for policy in from_db_rls_policies
        if policy.name not in [to_policy.name for to_policy in to_db_rls_policies]
    ]

    operations += [
        AlterPolicy(model_name, policy.name, policy.using, policy.check)
        for policy in altered_policies
    ]
    operations += [
        AddPolicy(model_name, policy.name, policy.using, policy.check)
        for policy in new_policies
    ]
    operations += [
        RemovePolicy(model_name, policy.name, policy.using, policy.check)
        for policy in removed_policies
    ]

    return operations if operations else None


registry.register(rls_changes)


class DjangoDbRlsConfig(AppConfig):
    name = "django_db_rls"
