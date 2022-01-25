from contextlib import redirect_stderr
from django.shortcuts import render, redirect
from main.models import Password
from .forms import RegisterForm
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from mechanize import Browser
import favicon
from django.contrib.auth.models import User
from django.conf import settings
from cryptography.fernet import Fernet
from password_strength import PasswordStats
from django.shortcuts import render, redirect
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
import re

# Create your views here.
br = Browser()
br.set_handle_robots(False)
key = Fernet.generate_key()
fernet = Fernet(settings.KEY)


def home(response):
    if response.method == 'POST':
        if 'add-password' in response.POST:
            url = response.POST.get('url')
            username = response.POST.get('username')
            email = response.POST.get('email')
            password = response.POST.get('password')
            if re.match("https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)", url) \
                    and (re.match('[a-zA-Z0-9][a-zA-Z0-9-_.]{1,200}', username) or username == '') \
                    and (re.match('(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email) or email == '') \
                    and re.match('[a-zA-Z0-9][a-zA-Z0-9-_.]{1,200}', password):
                grade = PasswordStats(password)
                encrypted_password = fernet.encrypt(password.encode())
                try:
                    br.open(url)
                    title = br.title()
                except:
                    title = url

                try:
                    icon = favicon.get(url)[0].url

                except:
                    icon = 'https://cdn-icons-png.flaticon.com/128/1006/1006771.png'

                new_password = Password.objects.create(
                    user=response.user,
                    name=title,
                    logo=icon,
                    username=username,
                    password=encrypted_password.decode(),
                    email=email,
                    grade=grade.strength()
                )
                new_password.save()

        elif 'delete-password' in response.POST:
            to_delete = response.POST.get('password-id')
            Password.objects.get(id=to_delete).delete()

        elif 'change-password' in response.POST:
            to_change = response.POST.get('password-id')
            new_password = response.POST.get('cardInput')
            encrypted_password = fernet.encrypt(new_password.encode()).decode()
            grade = PasswordStats(new_password)
            password = Password.objects.get(id=to_change)
            password.password = encrypted_password
            password.grade = grade.strength()
            password.save()

        elif 'grant-access' in response.POST:
            to_change = response.POST.get('password-id')
            coowner = response.POST.get('cardInput')
            if User.objects.filter(username=coowner).exists():
                coowner = User.objects.get(username=coowner)
                password = Password.objects.get(id=to_change)
                password.authorized.add(coowner)
                password.save()

    if response.user.is_authenticated:
        passwords = Password.objects.all().filter(user=response.user)
        for password in passwords:
            password.password = fernet.decrypt(
                password.password.encode()).decode()
        authorized = response.user.coowner.all()
        for password in authorized:
            password.password = fernet.decrypt(
                password.password.encode()).decode()
    else:
        passwords = []
        authorized = []
    return render(response, 'main/home.html', {'passwords': passwords, 'authorized': authorized})


def register(response):
    if response.method == 'POST':
        form = RegisterForm(response.POST)
        if form.is_valid():
            form.save()
            return redirect('/')
    else:
        form = RegisterForm()
    return render(response, 'registration/register.html', {'form': form})


def change_password(response):
    if response.method == 'POST':
        form = PasswordChangeForm(response.user, response.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(response, user)
            return redirect('/')
    else:
        form = PasswordChangeForm(response.user)
    return render(response, 'registration/change_password.html', {
        'form': form
    })


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password/password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': '127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'admin@example.com',
                                  [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect("/password_reset/done/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password/password_reset.html", context={"password_reset_form": password_reset_form})
