from django.db import transaction
from django_db_rls.db_utils import set_config


def atomic_request_middleware(get_response):

    # Option 1: Blunt force similar to ATOMIC_REQUESTS but in middleware
    def middleware(request):
        return get_response(request)
        if request.user.is_authenticated:
            with transaction.atomic():
                set_config("app.user", request.user.pk)
                return get_response(request)
        else:
            return get_response(request)

    # unfortunately this gets processed after the middleware function
    def process_view(request, view_func, view_args, view_kwargs):
        if getattr(view_func, "_non_atomic_requests", False):
            # no joy here
            request.non_atomic = True
        return None

    # Option 2: Selective, let people manage their own txns but make sure that template responses are also rendered correctly.
    def process_template_response(request, response):
        if request.user.is_authenticated:
            with transaction.atomic():
                set_config("app.user", request.user.pk)
                # force render
                # this would mean this middleware needs to be before any other rendering middleware so it is applied last
                response.content = response.render()
                return response
        else:
            return response

    middleware.process_view = process_view
    middleware.process_template_response = process_template_response

    return middleware
