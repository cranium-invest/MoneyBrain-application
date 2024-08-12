# paypal_utils.py

import requests
from django.conf import settings

def get_paypal_token():
    url = f"{settings.PAYPAL_API_BASE_URL}/v1/oauth2/token"
    headers = {
        'Authorization': f'Basic {settings.PAYPAL_CLIENT_ID}:{settings.PAYPAL_CLIENT_SECRET}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials'
    }
    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()['access_token']


def create_payouts(sender_batch_id, items, email_subject, email_message):
    url = f"{settings.PAYPAL_API_BASE_URL}/v1/payments/payouts"
    token = get_paypal_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {
        "sender_batch_header": {
            "sender_batch_id": sender_batch_id,
            "email_subject": email_subject,
            "email_message": email_message
        },
        "items": items
    }
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def get_payout_batch_details(payout_batch_id):
    url = f"{settings.PAYPAL_API_BASE_URL}/v1/payments/payouts/{payout_batch_id}"
    token = get_paypal_token()
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_payout_item_details(payout_item_id):
    url = f"{settings.PAYPAL_API_BASE_URL}/v1/payments/payouts-item/{payout_item_id}"
    token = get_paypal_token()
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def cancel_payout_item(payout_item_id):
    url = f"{settings.PAYPAL_API_BASE_URL}/v1/payments/payouts-item/{payout_item_id}/cancel"
    token = get_paypal_token()
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.json()