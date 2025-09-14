from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS, connections

# for a non-migrating user, need:
#  - SELECT, INSERT, UPDATE, DELETE for tables
#  - SELECT, USAGE for sequences

# for a migrating user, need to include CREATE

create_rls_role = """\
CREATE ROLE {role} WITH LOGIN NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO {role};

-- Necessary when unprivileged role will be used for migrations
GRANT CREATE ON SCHEMA public TO {role};
-- Necessary for CREATE EXTENSION
GRANT CREATE ON DATABASE {database} TO {role};

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role};

GRANT SELECT, USAGE ON ALL SEQUENCES IN SCHEMA public TO {role};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role};

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {role};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {role};

GRANT SET ON PARAMETER "app.user" TO {role};
"""

drop_rls_role = """\
DROP OWNED BY {role};
DROP ROLE {role};
"""


class Command(BaseCommand):
    help = "Setup an unprivileged role"

    def add_arguments(self, parser):
        parser.add_argument("role_name")
        parser.add_argument("-r", "--remove", action="store_true")
        parser.add_argument(
            "--database",
            default=DEFAULT_DB_ALIAS,
            choices=tuple(connections),
            help=('Nominates a database. Defaults to the "default" database.'),
        )

    def handle(self, *args, **options):
        db_alias = options["database"]
        database_name = connections[db_alias].settings_dict["NAME"]
        with connections[db_alias].cursor() as cursor:
            role_name = options["role_name"]
            sql = (drop_rls_role if options["remove"] else create_rls_role).format(
                role=role_name,
                database=database_name,
            )
            cursor.execute(sql)
            verb = "removed" if options["remove"] else "created"
            message = f'Role "{role_name}" {verb}'
            self.stdout.write(self.style.SUCCESS(message))
