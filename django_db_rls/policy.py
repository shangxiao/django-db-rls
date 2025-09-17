from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models import Exists
from django.db.models.sql.query import Query

from django_db_rls.db_utils import AppUser

User = get_user_model()


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
                # pscyopg2
                if isinstance(self.using, bytes):
                    self.using = self.using.decode("utf-8")

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
                    # pscyopg2
                    if isinstance(self.using, bytes):
                        self.using = self.using.decode("utf-8")

    def __eq__(self, other):
        return (
            self.name == other.name
            and self.using == other.using
            and self.check == other.check
        )


class IsSuperuserPolicy(Policy):
    """
    Allow Django is_superuser users (not to be confused with postgres SUPERUSER)
    """

    def __init__(self, name="is_superuser"):
        super().__init__(
            using=lambda: Exists(User.objects.filter(pk=AppUser(), is_superuser=True)),
            name=name,
        )
