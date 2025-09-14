from django.db import connection
from django.db.migrations.operations.base import Operation, OperationCategory
from django.db.models.sql.query import Query


def set_config(param, value):
    if not connection.in_atomic_block:
        raise RuntimeError("Must be within atomic")

    with connection.cursor() as cursor:
        if value is None or value == "":
            cursor.execute("select set_config(%s, '', true)", [param])
            return

        cursor.execute("select current_setting(%s, true)", [param])
        curr_value = cursor.fetchone()[0]
        if curr_value == str(value):
            return
        elif curr_value is None or curr_value == "":
            cursor.execute("select set_config(%s, %s, true)", [param, str(value)])
        else:
            raise RuntimeError("Cannot change config within another config")


class Policy:
    def __init__(self, *, using, check=None, name=None):
        self.using = using
        self.check = check
        self.name = name

    def compile(self, model):
        if self.name is None:
            self.name = f"{model._meta.model_name}_policy"

        if callable(self.using):
            self.using = self.using()
        if isinstance(self.using, str):
            pass
        else:
            query = Query(model=model)  # must alias_cols!
            where = query.build_where(self.using)
            compiler = query.get_compiler(connection=connection)
            using, params = where.as_sql(compiler, connection)
            with connection.cursor() as cur:
                self.using = cur.mogrify(using, params)

        if self.check:
            if callable(self.check):
                self.check = self.check()
            if isinstance(self.check, str):
                pass
            else:
                query = Query(model=model)  # must alias_cols!
                where = query.build_where(self.check)
                compiler = query.get_compiler(connection=connection)
                check, params = where.as_sql(compiler, connection)
                with connection.cursor() as cur:
                    self.check = cur.mogrify(check, params)

    def __eq__(self, other):
        return (
            self.name == other.name
            and self.using == other.using
            and self.check == other.check
        )


def enable_rls(schema_editor, model):
    table = schema_editor.quote_name(model._meta.db_table)
    schema_editor.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")


def disable_rls(schema_editor, model):
    table = schema_editor.quote_name(model._meta.db_table)
    schema_editor.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")


def create_policy(schema_editor, policy_name, model, using, check):
    table = schema_editor.quote_name(model._meta.db_table)
    policy = schema_editor.quote_name(policy_name)
    sql = f"CREATE POLICY {policy} ON {table} USING ({using})"
    if check:
        sql += f" WITH CHECK ({check})"
    schema_editor.execute(sql)


def drop_policy(schema_editor, policy_name, model):
    table = schema_editor.quote_name(model._meta.db_table)
    policy = schema_editor.quote_name(policy_name)
    schema_editor.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")


def alter_policy(schema_editor, policy_name, model, condition):
    table = schema_editor.quote_name(model._meta.db_table)
    schema_editor.execute(
        f"ALTER POLICY {schema_editor.quote_name(policy_name)} ON {table} USING ({condition}) WITH CHECK ({condition})"
    )


class AlterRLS(Operation):
    category = OperationCategory.ALTERATION

    def __init__(self, model_name, db_rls):
        self.model_name = model_name
        self.db_rls = db_rls

    def state_forwards(self, app_label, state):
        state.alter_model_options(app_label, self.model_name, {"db_rls": self.db_rls})

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)

        if getattr(to_model._meta, "db_rls", False):
            enable_rls(schema_editor, to_model)
        else:
            disable_rls(schema_editor, to_model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        self.database_forwards(app_label, schema_editor, from_state, to_state)

    def describe(self):
        return "Alter Row Level Security"


class AddPolicy(Operation):
    category = OperationCategory.ADDITION

    def __init__(self, model_name, name, using, check):
        self.model_name = model_name
        self.name = name
        self.using = using
        self.check = check

    def state_forwards(self, app_label, state):
        # using this will require that db_rls_policies is already initialised as a []
        # state._append_option(
        #     app_label,
        #     self.model_name,
        #     "db_rls_policies",
        #     Policy(using=self.using, check=self.check, name=self.name),
        # )
        obj = Policy(using=self.using, check=self.check, name=self.name)
        model_state = state.models[app_label, self.model_name]
        # xxx initialisation reqd here
        model_state.options.setdefault("db_rls_policies", [])
        model_state.options["db_rls_policies"] = [
            *model_state.options["db_rls_policies"],
            obj,
        ]
        state.reload_model(app_label, self.model_name, delay=True)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        create_policy(schema_editor, self.name, to_model, self.using, self.check)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        drop_policy(schema_editor, self.name, to_model)

    def describe(self):
        return f"Create Policy {self.name}"


class RemovePolicy(Operation):
    category = OperationCategory.REMOVAL

    def __init__(self, model_name, name, using, check):
        self.model_name = model_name
        self.name = name
        self.using = using
        self.check = check

    def state_forwards(self, app_label, state):
        self._remove_option(app_label, self.model_name, "db_rls_policies", self.name)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        drop_policy(schema_editor, self.name, to_model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        create_policy(schema_editor, self.name, to_model, self.using, self.check)

    def describe(self):
        return f"Drop Policy {self.name}"


class AlterPolicy(Operation):
    category = OperationCategory.ALTERATION

    def __init__(self, model_name, name, using, check):
        self.model_name = model_name
        self.name = name
        self.using = using
        self.check = check

    def state_forwards(self, app_label, state):
        self._alter_option(
            app_label,
            self.model_name,
            "db_rls_policies",
            Policy(using=self.using, check=self.check, name=self.name),
        )

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        alter_policy(schema_editor, self.name, to_model, self.using, self.check)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        self.database_forwards(app_label, schema_editor, from_state, to_state)

    def describe(self):
        return f"Alter Policy {self.name}"
