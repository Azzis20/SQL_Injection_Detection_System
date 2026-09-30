from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import redirect, render

def login_view(request):
    error = None

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")

        # Safely fetch user by email without throwing MultipleObjectsReturned
        user_obj = User.objects.filter(email__iexact=email).first()
        username = user_obj.username if user_obj else None
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard:index")
        else:
            error = "Invalid email or password."

    return render(request, "accounts/login.html", {"error": error})