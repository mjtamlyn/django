import urlparse

from django.conf import settings
from django.core.urlresolvers import reverse_lazy
from django.http import HttpResponseRedirect, QueryDict
from django.utils.decorators import method_decorator
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
    """
    Add a current_app attribute on the view and pass it to the response class.
    """
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


class RedirectToMixin(object):
    """
    Provide a success_url that takes into account a request parameter (whose
    name is configurable).
    In the absence of this parameter, a (configurable) default URL is used.
    """
    redirect_field_name = REDIRECT_FIELD_NAME
    default_redirect_to = None

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_default_redirect_to(self):
        return self.default_redirect_to

    def get_success_url(self):
        default = self.get_default_redirect_to()
        redirect_to = self.request.REQUEST.get(self.get_redirect_field_name())
        return redirect_to or default


class ProtectectedRedirectToMixin(RedirectToMixin):
    """
    Ensure the URL to be redirected to is on the same host.
    """
    def get_success_url(self):
        redirect_to = super(ProtectectedRedirectToMixin, self).get_success_url()
        if self.is_valid_url(redirect_to):
            return redirect_to
        else:
            return self.get_default_redirect_to()

    def is_valid_url(self, url, allow_empty=True):
        if not url:
            return allow_empty
        netloc = urlparse.urlparse(url)[1]
        return not netloc or netloc == self.request.get_host()


class LoginView(ProtectectedRedirectToMixin, CurrentAppMixin, CurrentSiteMixin, generic.FormView):
    """
    Display the login form and handle the login action.
    """
    form_class = AuthenticationForm
    template_name = 'registration/login.html'

    default_redirect_to = settings.LOGIN_REDIRECT_URL

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        request.session.set_test_cookie()
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def form_valid(self, form):
        """Log the user in and redirect."""
        auth_login(self.request, form.get_user())

        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()

        # Redirect
        return super(LoginView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        context[self.get_redirect_field_name()] = self.get_success_url()
        return context


class LogoutView(ProtectectedRedirectToMixin, CurrentAppMixin, CurrentSiteMixin, generic.TemplateView):
    """
    Log out the user and display 'You are logged out' message.
    """
    template_name = 'registration/logged_out.html'

    def get_context_data(self, **kwargs):
        context = super(LogoutView, self).get_context_data(**kwargs)
        context['title'] = _('Logged out')
        return context

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        redirect_to = self.get_success_url()

        if redirect_to is not None:
            # Redirect to the current page if no default has been provided
            redirect_to = redirect_to or self.request.path
            return HttpResponseRedirect(redirect_to)

        # Render the template
        return super(LogoutView, self).get(request, *args, **kwargs)

    # XXX: define post(), put(), ... ?


class LogoutThenLoginView(LogoutView):
    """
    Log out the user if he is logged in. Then redirects to the log-in page.
    """
    success_url = None

    def get_success_url(self):
        return self.success_url or settings.LOGIN_URL


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

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordResetView, self).dispatch(request, *args, **kwargs)


class PasswordResetDoneView(CurrentAppMixin, generic.TemplateView):
    """
    Show a confirmation message that a password reset email has been sent.
    """
    template_name = "registration/password_reset_done.html"


class PasswordResetConfirmView(CurrentAppMixin, generic.UpdateView):
    # XXX: This one might have some backwards-compatibility issues in some corner cases.
    # In this CBV, form.user is a User instance if the token matches the uidb36,
    # even in the GET request, as opposed to the old view where form.user was
    # only set in POST).
    """
    Check that the given token is valid then prompt the user for a new pasword.
    """
    template_name = "registration/password_reset_confirm.html"
    form_class = SetPasswordForm
    success_url = reverse_lazy('django.contrib.auth.views.password_reset_complete')

    token_generator = default_token_generator

    def get_object(self, queryset=None):
        try:
            pk = base36_to_int(self.kwargs['uidb36'])
            user = User.objects.get(pk=pk)
        except (ValueError, User.DoesNotExist):
            return None

        if not self.token_generator.check_token(user, self.kwargs['token']):
            return None
        return user

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = kwargs.pop('instance')
        return kwargs

    def form_valid(self, form):
        if self.object is None:
            return self.form_invalid(form)
        return super(PasswordResetConfirmView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(PasswordResetConfirmView, self).get_context_data(**kwargs)
        context['validlink'] = self.object is not None
        return context

    # Doesn't need csrf_protect since no-one can guess the URL
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordResetConfirmView, self).dispatch(request, *args, **kwargs)


class PasswordResetComplete(CurrentAppMixin, generic.TemplateView):
    """
    Show a confirmation message that the user's password has been reset.
    """
    template_name = "registration/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        context = super(PasswordResetComplete, self).get_context_data(**kwargs)
        context['login_url'] = settings.LOGIN_URL
        return context


class PasswordChangeView(CurrentAppMixin, generic.UpdateView):
    """
    Prompt the logged-in user for  their old password and a new one and change
    the password if the old password is valid.
    """
    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy('django.contrib.auth.views.password_change_done')
    form_class = PasswordChangeForm

    def get_object(self, queryset=None):
        return self.request.user

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = kwargs.pop('instance')

        return kwargs

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(request, *args, **kwargs)


class PasswordChangeDoneView(CurrentAppMixin, generic.TemplateView):
    """
    Show a confirmation message that the user's password has been changed.
    """
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

def add_extra_context(cbv, **kwargs):
    extra_context = kwargs.pop('extra_context', {})
    class Wrapped(cbv):
        def get_context_data(self, **kwargs):
            context = super(cbv, self).get_context_data(**kwargs)
            context.update(extra_context)
            return context

    return Wrapped.as_view(**kwargs)

def login(request, template_name=None, redirect_field_name=None,
          authentication_form=None, current_app=None, extra_context=None):
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if redirect_field_name is not None:
        kwargs["redirect_field_name"] = redirect_field_name
    if authentication_form is not None:
        kwargs["form_class"] = authentication_form
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    view = add_extra_context(LoginView, **kwargs)
    return view(request)

def logout(request, next_page=None, template_name=None,
           redirect_field_name=None, current_app=None, extra_context=None):
    kwargs = {}

    if next_page is not None:
        kwargs["default_redirect_to"] = next_page
    if template_name is not None:
        kwargs["template_name"] = template_name
    if redirect_field_name is not None:
        kwargs["redirect_field_name"] = redirect_field_name
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    view = add_extra_context(LogoutView, **kwargs)
    return view(request)

def logout_then_login(request, login_url=None, current_app=None, extra_context=None):
    """
    Logs out the user if he is logged in. Then redirects to the log-in page.
    """
    kwargs = {}

    if login_url is not None:
        kwargs["success_url"] = login_url
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context
    view = add_extra_context(LogoutThenLoginView, **kwargs)
    return view(request)

def redirect_to_login(next, login_url=None,
                      redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Redirects the user to the login page, passing the given 'next' page
    """
    if not login_url:
        login_url = settings.LOGIN_URL

    login_url_parts = list(urlparse.urlparse(login_url))
    if redirect_field_name:
        querystring = QueryDict(login_url_parts[4], mutable=True)
        querystring[redirect_field_name] = next
        login_url_parts[4] = querystring.urlencode(safe='/')

    return HttpResponseRedirect(urlparse.urlunparse(login_url_parts))

def password_reset(request, is_admin_site=None, template_name=None,
                   email_template_name=None, subject_template_name=None,
                   password_reset_form=None, token_generator=None,
                   post_reset_redirect=None, from_email=None, current_app=None,
                   extra_context=None):
    kwargs = {}

    if is_admin_site is not None:
        kwargs["is_admin_site"] = is_admin_site
    if template_name is not None:
        kwargs["template_name"] = template_name
    if email_template_name is not None:
        kwargs["email_template_name"] = email_template_name
    if password_reset_form is not None:
        kwargs["form_class"] = password_reset_form
    if token_generator is not None:
        kwargs["token_generator"] = token_generator
    if post_reset_redirect is not None:
        kwargs["success_url"] = post_reset_redirect
    if from_email is not None:
        kwargs["from_email"] = from_email
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_reset = add_extra_context(PasswordResetView, **kwargs)
    return password_reset(request)

def password_reset_done(request, template_name=None, current_app=None,
                        extra_context=None):
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_reset_done = add_extra_context(PasswordResetDoneView, **kwargs)
    return password_reset_done(request)

def password_reset_confirm(request, uidb36=None, token=None,
                           template_name=None, token_generator=None,
                           set_password_form=None, post_reset_redirect=None,
                           current_app=None, extra_context=None):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    assert uidb36 is not None and token is not None  # checked by URLconf
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if token_generator is not None:
        kwargs["token_generator"] = token_generator
    if set_password_form is not None:
        kwargs["form_class"] = set_password_form
    if post_reset_redirect is not None:
        kwargs["success_url"] = post_reset_redirect
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_reset_confirm = add_extra_context(PasswordResetConfirmView, **kwargs)
    return password_reset_confirm(request, uidb36=uidb36, token=token)

def password_reset_complete(request, template_name=None, current_app=None,
                            extra_context=None):
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_reset_complete = add_extra_context(PasswordResetComplete, **kwargs)
    return password_reset_complete(request)

def password_change(request, template_name=None, post_change_redirect=None,
                    password_change_form=None, current_app=None,
                    extra_context=None):
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if post_change_redirect is not None:
        kwargs["success_url"] = post_change_redirect
    if password_change_form is not None:
        kwargs["form_class"] = password_change_form
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_change = add_extra_context(PasswordChangeView, **kwargs)
    return password_change(request)

def password_change_done(request, template_name=None, current_app=None,
                            extra_context=None):
    kwargs = {}

    if template_name is not None:
        kwargs["template_name"] = template_name
    if current_app is not None:
        kwargs["current_app"] = current_app
    if extra_context is not None:
        kwargs["extra_context"] = extra_context

    password_change_done = add_extra_context(PasswordChangeDoneView, **kwargs)
    return password_change_done(request)
