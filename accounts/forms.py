# from django import forms
# from django.contrib.auth import authenticate
# from django.utils.translation import gettext_lazy as _


# class EmailLoginForm(forms.Form):
#     """
#     Login form that collects an email address and password, then
#     authenticates the user via the custom EmailBackend.
#     """

#     email = forms.EmailField(
#         label=_("Email address"),
#         max_length=254,
#         widget=forms.EmailInput(
#             attrs={
#                 "autofocus": True,
#                 "autocomplete": "email",
#                 "placeholder": "you@example.com",
#                 "class": "form-input",
#             }
#         ),
#     )
#     password = forms.CharField(
#         label=_("Password"),
#         strip=False,
#         widget=forms.PasswordInput(
#             attrs={
#                 "autocomplete": "current-password",
#                 "placeholder": "••••••••",
#                 "class": "form-input",
#             }
#         ),
#     )

#     error_messages = {
#         "invalid_login": _(
#             "Please enter a correct email address and password. "
#             "Both fields may be case-sensitive."
#         ),
#         "inactive": _("This account is inactive."),
#     }

#     def __init__(self, request=None, *args, **kwargs):
#         self.request = request
#         self.user_cache = None
#         super().__init__(*args, **kwargs)

#     def clean(self):
#         email = self.cleaned_data.get("email")
#         password = self.cleaned_data.get("password")

#         if email and password:
#             self.user_cache = authenticate(
#                 self.request, username=email, email=email, password=password
#             )
#             if self.user_cache is None:
#                 raise forms.ValidationError(
#                     self.error_messages["invalid_login"], code="invalid_login"
#                 )
#             if not self.user_cache.is_active:
#                 raise forms.ValidationError(
#                     self.error_messages["inactive"], code="inactive"
#                 )
#         return self.cleaned_data

#     def get_user(self):
#         return self.user_cache