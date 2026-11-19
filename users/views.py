from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    RegisterSerializer,
)


class RegisterView(APIView):
    """POST /api/users/register/  {username, password}"""

    # Open to everyone. authentication_classes = [] means a stale or wrong
    # token in the request header can't block registering or logging in.
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {
                "user": {"id": user.id, "username": user.username},
                "token": token.key,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    """POST /api/users/login/  {username, password}"""

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {
                "user": {"id": user.id, "username": user.username},
                "token": token.key,
            }
        )


class ChangePasswordView(APIView):
    """POST /api/users/change-password/  {old_password, new_password}

    Requires the header:  Authorization: Token <your token>
    (The default permission, IsAuthenticated, is set in settings.py.)
    """

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        # Replace the token so any old token stops working.
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)

        return Response({"detail": "Password changed.", "token": token.key})