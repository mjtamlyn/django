import copy

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:     # Python 2
    from urlparse import urlparse, urlunparse

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.urlresolvers import reverse_lazy
from django.http import HttpResponseRedirect, QueryDict
from django.utils.decorators import method_decorator
from django.utils.encoding import force_str
from django.utils.http import base36_to_int
from django.utils.translation import ugettext as _
from django.views import generic
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site


class CurrentAppMixin(object):
    """Add a current_app attribute on the view and pass it to the response class."""
    current_app = None

    def render_to_response(self, context, **response_kwargs):
        return self.response_class(
            request=self.request,
            template=self.get_template_names(),
            context=context,
            current_app=self.current_app,
            **response_kwargs
        )


class CurrentSiteMixin(object):
    """Add the current site to the context."""
    def get_context_data(self, **kwargs):
        context = super(CurrentSiteMixin, self).get_context_data(**kwargs)

        current_site = get_current_site(self.request)
        context.update({
            "site": current_site,
            "site_name": current_site.name,
        })
        return context


def validate_redirect_url(url, request, allow_empty=False):
    """"Validate that ``url`` is a valid URL for use in redirections.

    Raise ValidationError if:

    * ``allow_empty`` is False and ``url`` is empty string.
    * URL is not on the same host as the given request.

    """
    if not url:
        if not allow_empty:
            raise ValidationError("URL can't be empty.")
    else:
        netloc = urlparse(url)[1]
        request_host = request.get_host()
        if netloc and netloc != request_host:
            raise ValidationError("URL must belong to '%s' host."
                                  % request_host)
    return url


class LoginView(CurrentAppMixin, CurrentSiteMixin, generic.FormView):
    """Display the login form and handle the login action."""
    form_class = AuthenticationForm
    template_name = 'registration/login.html'

    redirect_field_name = REDIRECT_FIELD_NAME

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self.set_test_cookie(request)
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        context[self.redirect_field_name] = self.get_success_url()
        return context

    def login(self, user):
        """Log user in."""
        auth_login(self.request, user)

    def set_test_cookie(self, request):
        """Set test cookie to request."""
        request.session.set_test_cookie()

    def unset_test_cookie(self):
        """Cleanup test cookie if necessary."""
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()

    def form_valid(self, form):
        """Log the user in and redirect."""
        self.login(form.get_user())
        self.unset_test_cookie()
        # Redirect
        return super(LoginView, self).form_valid(form)

    def get_success_url(self):
        """
        Look for a redirect URL in the request parameters.
        If none is found, or if it's not valid, use settings.LOGIN_REDIRECT_URL.

        """
        redir = self.request.REQUEST.get(self.redirect_field_name)
        try:
            redir = validate_redirect_url(redir, self.request,
                                          allow_empty=False)
        except ValidationError:
            # Silently fallback to view's ``success_url``.
            try:
                redir = super(LoginView, self).get_success_url()
            except ImproperlyConfigured:
                # Silently fallback to settings.
                redir = settings.LOGIN_REDIRECT_URL
        return redir


class LogoutView(CurrentAppMixin, CurrentSiteMixin, generic.TemplateView):
    """Log out the user and display 'You are logged out' message."""
    template_name = 'registration/logged_out.html'
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = None

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        redir = self.get_success_url()

        if redir is not None:
            return HttpResponseRedirect(redir)
        else:
            # Render the template
            return super(LogoutView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(LogoutView, self).get_context_data(**kwargs)
        context['title'] = _('Logged out')
        return context

    def get_success_url(self):
        """
        Look for a url to redirect to in the request parameters.
        If none is found, or if it's not valid, fall back on the
        view instance's success_url attribute.
        If that attribute has not been set (None), then return None.
        If it has but it's empty, return the current request's path.

        """
        redir = self.request.REQUEST.get(self.redirect_field_name)
        try:
            return validate_redirect_url(redir, self.request,
                                         allow_empty=False)
        except ValidationError:
            # Silently fallback to view's ``success_url``.
            try:
                return super(LogoutView, self).get_success_url()
            except ImproperlyConfigured:
                # Silently fallback to current request.path if success_url has
                # been set to empty value (except None).
                if self.success_url is not None:
                    return self.request.path
                else:
                    # Silently fallback to None.
                    return None


class LogoutThenLoginView(LogoutView):
    """Log out the user if he is logged in. Then redirects to the log-in page."""
    success_url = settings.LOGIN_URL


class PasswordResetView(CurrentAppMixin, generic.FormView):
    """
    Ask for the user's email address and send a message containing a token
    allowing to reset the user's password.

    """
    template_name = "registration/password_reset_form.html"
    form_class = PasswordResetForm
    success_url = reverse_lazy('django.contrib.auth.views.password_reset_done')

    is_admin_site = False
    email_template_name = "registration/password_reset_email.html"
    subject_template_name = "registration/password_reset_subject.txt"
    token_generator = default_token_generator
    from_email = None

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordResetView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': self.token_generator,
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
        }
        if self.is_admin_site:
            opts['domain_override'] = self.request.META['HTTP_HOST']
        form.save(**opts)
        return super(PasswordResetView, self).form_valid(form)


class PasswordResetDoneView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that a password reset email has been sent."""
    template_name = "registration/password_reset_done.html"


class PasswordResetConfirmView(CurrentAppMixin, generic.FormView):
    # XXX: This one might have some backwards-compatibility issues in some corner cases.
    # In this CBV, form.user is a User instance if the token matches the uidb36,
    # even in the GET request, as opposed to the old view where form.user was
    # only set in POST).
    """
    Check that the given token is valid and prompt the user for a new pasword.
    Then update the user's password with this new one.

    """
    template_name = "registration/password_reset_confirm.html"
    form_class = SetPasswordForm
    success_url = reverse_lazy('django.contrib.auth.views.password_reset_complete')

    token_generator = default_token_generator

    # Doesn't need csrf_protect since no-one can guess the URL
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self.user = self.get_user(**kwargs)
        return super(PasswordResetConfirmView, self).dispatch(request, *args, **kwargs)

    def get_user(self, **kwargs):
        """Try to retrieve the user corresponding to the uid captured in the URL.
        If no user is found, or if the user found does not match the token in
        the URL, return None.
        
        """
        try:
            pk = base36_to_int(kwargs['uidb36'])
            user = User.objects.get(pk=pk)
        except (ValueError, OverflowError, User.DoesNotExist):
            return None

        if not self.token_generator.check_token(user, kwargs['token']):
            return None
        return user

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(PasswordResetConfirmView, self).get_context_data(**kwargs)
        context['validlink'] = self.user is not None
        return context

    def form_valid(self, form):
        form.save()
        return super(PasswordResetConfirmView, self).form_valid(form)


class PasswordResetCompleteView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that the user's password has been reset."""
    template_name = "registration/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        context = super(PasswordResetCompleteView, self).get_context_data(**kwargs)
        context['login_url'] = settings.LOGIN_URL
        return context


class PasswordChangeView(CurrentAppMixin, generic.FormView):
    """
    Prompt the logged-in user for their current password as well as a new one.
    If the current password is valid, change it to the new one.

    """
    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy('django.contrib.auth.views.password_change_done')
    form_class = PasswordChangeForm

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = self.request.user

        return kwargs

    def form_valid(self, form):
        form.save()
        return super(PasswordChangeView, self).form_valid(form)


class PasswordChangeDoneView(CurrentAppMixin, generic.TemplateView):
    """Show a confirmation message that the user's password has been changed."""
    template_name = "registration/password_change_done.html"

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeDoneView, self).dispatch(request, *args, **kwargs)


# Backwards-compatible stubs that call the class-based views:
# login
# logout
# logout_then_login
# redirect_to_login (not actually a view)
# password_reset
# password_reset_done
# password_reset_confirm
# password_reset_complete
# password_change
# password_change_done

def cbv_wrapper(cbv, initkwarg_rewrites=None):
    def wrapped(request, *args, **kwargs):
        extra_context = kwargs.pop('extra_context', {})
        initkwargs = copy.copy(kwargs)
        if initkwarg_rewrites:
            for old, new in initkwarg_rewrites.items():
                if old in initkwargs:
                    value = initkwargs.pop(old)
                    if new:
                        initkwargs[new] = value
        view = cbv.as_view(**initkwargs)
        response = view(request, *args, **kwargs)
        if hasattr(response, 'context_data'):
            # don't try to update context on Redirects
            response.context_data.update(extra_context)
        return response
    return wrapped

login = cbv_wrapper(LoginView, {'authentication_form': 'form_class'})
logout = cbv_wrapper(LogoutView, {'next_page': 'success_url'})
logout_then_login = cbv_wrapper(LogoutThenLoginView, {'login_url': 'success_url'})
password_reset = cbv_wrapper(PasswordResetView, {'password_reset_form': 'form_class'})
password_reset_done = cbv_wrapper(PasswordResetDoneView)
password_reset_confirm = cbv_wrapper(PasswordResetConfirmView, {'uidb36': None, 'token': None, 'set_password_form': 'form_class', 'post_reset_redirect': 'success_url'})
password_reset_complete = cbv_wrapper(PasswordResetCompleteView)
password_change = cbv_wrapper(PasswordChangeView, {'post_change_redirect': 'success_url', 'password_change_form': 'form_class'})
password_change_done = cbv_wrapper(PasswordChangeDoneView)

def redirect_to_login(next, login_url=None,
                      redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Redirects the user to the login page, passing the given 'next' page
    """
    # urlparse chokes on lazy objects in Python 3
    login_url_as_str = force_str(login_url or settings.LOGIN_URL)

    login_url_parts = list(urlparse(login_url_as_str))
    if redirect_field_name:
        querystring = QueryDict(login_url_parts[4], mutable=True)
        querystring[redirect_field_name] = next
        login_url_parts[4] = querystring.urlencode(safe='/')

    return HttpResponseRedirect(urlunparse(login_url_parts))
