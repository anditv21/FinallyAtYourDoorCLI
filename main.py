import os
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

import aiohttp
import asyncio
import auth
import json
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

url = "https://api.post.at/bff/auth/shipments"

headers_template = {
  "Accept": "application/json",
  "Content-Type": "application/json",
  "User-Agent": "Android"
}

query_shipments_string = "query ShipmentList($elementcount: Int!, $previousSendungenCount: Int!) { pagedSendungen: sendungen(postProcessingOptions: { elementCount: $elementcount previousSendungenCount: $previousSendungenCount sortByDate: DESCENDING paging: RECEIVE_AND_SEND } ) { totalSendungen versandSendungen empfangsSendungen sendungen { activeIdentityCode originalIdentityCode bezeichnung bild branchkey status isMeineSendung tags { key } lastEventDate isRecipient weight sender produktkategorie hasNewFlag hasPayment preshipper substituteRecipient paymentInformation { ssoSignInNecessary payableAmounts { amount amountPaid dueDate type } } ssoidmatch parcelStampId parcelStampValidTo notificationInformation { amount claim endOfStorageDate notificationIdentifier ssoUserIdList storage storageLimit } codInformation { amount currency } customsInformation { customsDocumentAvailable userDocumentNeeded } recipient { name postCode street } recipientAddress { consigneeName consigneeAdditionalStreet consigneeStreetNr consigneePostalCode consigneeStreet } estimatedDelivery { startDate startTime endDate endTime } dimensions { height length width } sendungsEvents { eventcountry eventpostalcode trackingStateKey text textEn timestamp } packageRedirections { customdeliveryday { customDeliveryDates estimatedDelivery isSelected selectedCustomDeliveryDay } neighbor { firstname isSelected lastname street streetNr } parcellocker { isSelected selectedBranch selectedRedirectionAreaCode } place { beschreibung isSelected } postoffice { isSelected selectedBranch selectedRedirectionAreaCode } } } } }"

def print_success_message(text):
    time = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
    print(f"[{time}] [{Fore.LIGHTCYAN_EX}SUCCESS{Fore.RESET}] [\u2705] {text}")

def print_failure_message(text):
    time = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
    print(f"[{time}] [{Fore.RED}ERROR{Fore.RESET}] [\u274C] {text}")

def print_info_message(text):
    time = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
    print(f"[{time}] [{Fore.LIGHTCYAN_EX}INFO{Fore.RESET}] [ℹ️] {text}")

async def check_and_redirect():
  try:
    token = await auth.get_token_auto_async(prompt=False, debug=False)
  except Exception as e:
    print_failure_message(f"Failed to get token: {e}")
    return

  headers = {**headers_template, "Authorization": f"Bearer {token}"}

  query_shipments = {
    "operationName": "ShipmentList",
    "variables": {"elementcount": 10, "previousSendungenCount": 0},
    "query": query_shipments_string,
    "extensions": {"clientLibrary": {"name": "apollo-kotlin", "version": "4.3.1"}}
  }

  async with aiohttp.ClientSession() as session:

    # Get shipments
    async with session.post(url, headers=headers, json=query_shipments) as resp:
      text = await resp.text()
      if not text or text.strip() == "":
        print_info_message("Empty response body; shipment information may not be transmitted yet")
        shipments_data = None
        response_data = None
      else:
        try:
          response_data = json.loads(text)
          shipments_data = response_data.get('data') if isinstance(response_data, dict) else None
        except Exception as e:
          excerpt = text[:200].replace('\n', ' ')
          print_info_message(f"Failed to parse response: {e}; response excerpt: {excerpt}")
          shipments_data = None
          response_data = None

    # If unauthorized or missing data, try refreshing token once
    if shipments_data is None or 'pagedSendungen' not in shipments_data:
      status401 = isinstance(response_data, dict) and response_data.get('statusCode') == 401

      if status401:
        try:
          token = await auth.get_token_auto_async(prompt=False, debug=False)
          headers = {**headers_template, "Authorization": f"Bearer {token}"}
          async with session.post(url, headers=headers, json=query_shipments) as resp2:
            response_data = await resp2.json()
            shipments_data = response_data.get('data') if isinstance(response_data, dict) else None
        except Exception as e:
          print_failure_message(f"Token refresh failed: {e}")
          return

    if not shipments_data or 'pagedSendungen' not in shipments_data:
      print_info_message("No data in response; shipment information may not be transmitted yet")
      return

    print_success_message("Shipments fetched")

    paged = shipments_data.get('pagedSendungen') or {}
    sendungen = paged.get('sendungen') or []
    for sendung in sendungen:
        if sendung.get('status') != 'ZU':
            sendungsnummer = sendung.get('activeIdentityCode')
            if not sendungsnummer:
                print_failure_message("Missing activeIdentityCode, skipping shipment")
                continue
            print_info_message(f"Processing {sendungsnummer}")

            # Check if place redirection is already selected
            package_redirs = sendung.get('packageRedirections') or []
            already_redirected = any((redir.get('place') or {}).get('isSelected', False) for redir in package_redirs)
            if already_redirected:
                continue

            # Get possible redirections
            query_redir = {
                "operationName": "PossibleRedirections",
                "variables": {"sendungsnummer": sendungsnummer},
                "query": "query PossibleRedirections($sendungsnummer: String!) { einzelsendung(sendungsnummer: $sendungsnummer) { activeIdentityCode possibleRedirections { abholstation abstellort datum filliale nachbar zustelldatum branchesParcelLocker branchesPostOffice redirectionAreaCode } } }",
                "extensions": {"clientLibrary": {"name": "apollo-kotlin", "version": "4.3.1"}}
            }

            try:
              async with session.post(url, headers=headers, json=query_redir) as resp:
                text = await resp.text()
                if resp.status != 200:
                  excerpt = text[:200].replace('\n', ' ')
                  print_info_message(f"Failed to get redirections for {sendungsnummer}: status={resp.status}; response excerpt: {excerpt}")
                  redir_data = None
                else:
                  try:
                    redir_response = json.loads(text)
                    redir_data = redir_response.get('data') if isinstance(redir_response, dict) else None
                  except Exception as e:
                    excerpt = text[:200].replace('\n', ' ')
                    print_info_message(f"Failed to parse redirections for {sendungsnummer}: {e}; response excerpt: {excerpt}")
                    redir_data = None
            except Exception as e:
              print_failure_message(f"Failed to get redirections for {sendungsnummer}: {e}")
              continue

            if redir_data:
                einzelsendung = redir_data.get('einzelsendung') or {}
                possible_redirs = einzelsendung.get('possibleRedirections') or {}
                if possible_redirs.get('abstellort'):
                    # set redirection
                    query_mut = {
                    "operationName": "RedirectShipmentPlace",
                    "variables": {
                        "redirectionRequest": {
                            "abstellort": "Vor_Wohnungstüre",
                            "beschreibung": "",
                            "sendungsnummer": sendungsnummer
                        }
                    },
                    "query": "mutation RedirectShipmentPlace($redirectionRequest: PlaceRedirectionType!) { setPlaceRedirection(redirection: $redirectionRequest) }",
                    "extensions": {"clientLibrary": {"name": "apollo-kotlin", "version": "4.3.1"}}
                    }

                    try:
                        async with session.post(url, headers=headers, json=query_mut) as resp:
                            mut_response = await resp.json()
                            mut_data = mut_response.get('data') if isinstance(mut_response, dict) else None

                        if mut_data:
                            print_success_message(f"Redirected {sendungsnummer} to Vor_Wohnungstüre")
                        else:
                            print_failure_message(f"Failed to redirect {sendungsnummer}")
                    except Exception as e:
                        print_failure_message(f"Error redirecting {sendungsnummer}: {e}")
                else:
                    print_info_message(f"Redirection not yet available for {sendungsnummer}, shipment information may not be transmitted yet")
            else:
                print_info_message(f"No redirection data available for {sendungsnummer}, shipment information may not be transmitted yet")

async def main():
    print_info_message("Starting shipment auto-redirect bot")

    while True:
        try:
            await check_and_redirect()
        except Exception as e:
            print_failure_message(f"Error in main loop: {e}")

        print_info_message("Waiting 10 minutes until next check...")
        await asyncio.sleep(600)

asyncio.run(main())
