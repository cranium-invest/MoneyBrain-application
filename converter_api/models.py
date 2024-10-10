from django.db import models
from django.contrib.auth.models import User

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    recipient_account = models.EmailField()
    status = models.CharField(max_length=50, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    payment_id = models.CharField(max_length=255, blank=True, null=True)
    payer_id = models.CharField(max_length=255, blank=True, null=True)

class UploadedImage(models.Model):
    back_image = models.ImageField(upload_to='uploads/')
    front_image = models.ImageField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    client_id = models.CharField(max_length=100, unique=True, blank=True, null=True)

class GHSTransaction(models.Model):
    transaction_id = models.CharField(max_length=255, unique=True)
    phone_number = models.CharField(max_length=15)
    mobile_provider = models.CharField(max_length=20)
    ux_flow = models.CharField(max_length=100, default='ussd_popup')
    status = models.CharField(max_length=20, default='initial')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Sender(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='senders')
    sender_id = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone_country = models.CharField(max_length=10)
    phone_number = models.CharField(max_length=20)
    country = models.CharField(max_length=3)  # ISO 3166-1 alpha-3
    city = models.CharField(max_length=255)
    street = models.CharField(max_length=255)
    postal_code = models.CharField(max_length=20)
    birth_date = models.DateField()
    document_file_name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.sender_id})"