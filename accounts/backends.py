# """
# Custom authentication backend that allows users to log in with their
# email address instead of a username.

# Add this to AUTHENTICATION_BACKENDS in settings.py:

#     AUTHENTICATION_BACKENDS = [
#         "yourapp.backends.EmailBackend",
#         "django.contrib.auth.backends.ModelBackend",  # keep as fallback
#     ]
# """

# from django.contrib.auth import get_user_model
# from django.contrib.auth.backends import ModelBackend

# User = get_user_model()


# class EmailBackend(ModelBackend):
#     """
#     Authenticates against the User model using email + password.
#     """

#     def authenticate(self, request, username=None, password=None, **kwargs):
#         # 'username' here is whatever value the login form passed in the
#         # first positional slot -- we treat it as the email address.
#         email = kwargs.get("email", username)
#         if email is None or password is None:
#             return None

#         try:
#             user = User.objects.get(email__iexact=email)
#         except User.DoesNotExist:
#             # Run the default hasher anyway to mitigate user-enumeration
#             # timing attacks (Django's own recommended pattern).
#             User().set_password(password)
#             return None
#         except User.MultipleObjectsReturned:
#             # Should not happen if email is enforced unique, but guard anyway.
#             user = User.objects.filter(email__iexact=email).order_by("id").first()

#         if user.check_password(password) and self.user_can_authenticate(user):
#             return user
#         return None

#     def get_user(self, user_id):
#         try:
#             user = User.objects.get(pk=user_id)
#         except User.DoesNotExist:
#             return None
#         return user if self.user_can_authenticate(user) else None