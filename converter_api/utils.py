
from django.views import View
from django.conf import settings
import requests
from django.http import JsonResponse

def get_quote(self, amount, destination_country):
        url = f"{self.base_url}/quote"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
        }
        data = {
            "amount": amount,
            "destination_country": destination_country,
        }
        response = requests.post(url, headers=headers, json=data)
        return response.json()

def update_transaction(self, transaction_id, sender_info, receiver_info):
        url = f"{self.base_url}/{transaction_id}"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
        }
        data = {
            "sender": sender_info,
            "receiver": receiver_info,
        }
        response = requests.put(url, headers=headers, json=data)
        return response.json()

def commit_transaction(self, transaction_id):
        url = f"{self.base_url}/{transaction_id}/commit"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
        }
        response = requests.put(url, headers=headers)
        return response.json()

def post(self, request, *args, **kwargs):
        # Example data; you will need to adjust according to your requirements
        amount = request.POST.get('amount')
        destination_country = request.POST.get('destination_country')
        sender_info = {
            # Sender's details
        }
        receiver_info = {
            # Receiver's details
        }
        
        quote_response = self.get_quote(amount, destination_country)
        transaction_id = quote_response.get('transactionId')

        if transaction_id:
            update_response = self.update_transaction(transaction_id, sender_info, receiver_info)
            commit_response = self.commit_transaction(transaction_id)
            return JsonResponse(commit_response)
        else:
            return JsonResponse(quote_response, status=400)