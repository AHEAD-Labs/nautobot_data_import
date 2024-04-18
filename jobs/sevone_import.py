import logging
import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar
from nautobot.extras.models import GraphQLQuery, SecretsGroup
from nautobot.extras.secrets.exceptions import SecretError

# Setup the logger using Nautobot's get_task_logger function
logger = get_task_logger(__name__)

class Sevone_Onboarding(Job):
    class Meta:
        name = "Device Onboarding from SevOne"
        description = "Onboards devices from SevOne by fetching and processing their details."

    sevone_api_url = StringVar(description="URL of the SevOne API", default="http://gbsasev-pas01/")
    sevone_credentials = ObjectVar(model=SecretsGroup, description="SevOne API Credentials")

    def run(self, sevone_api_url, sevone_credentials):
        logger.info("Starting device onboarding process.")
        devices = self.fetch_devices_from_sevone(sevone_api_url, sevone_credentials)
        if devices:
            return self.process_devices(devices)
        else:
            logger.info("No devices fetched from SevOne.")
            return "No devices were found."

    def fetch_devices_from_sevone(self, sevone_api_url, sevone_credentials):
        try:
            username = sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='username')
            password = sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='password')
            creds = {'name': username, 'password': password}
            auth_response = requests.post(f"{sevone_api_url}/authentication/signin", json=creds, headers={'Content-Type': 'application/json'})
            if auth_response.status_code != 200:
                logger.error(f"Authentication failed with status {auth_response.status_code}: {auth_response.text}")
                return []

            token = auth_response.json().get('token')
            session = requests.Session()
            session.headers.update({'Authorization': f'Bearer {token}'})
            devices_response = session.get(f"{sevone_api_url}/devices?page=0&size=10000")
            if devices_response.status_code != 200:
                logger.error(f"Failed to fetch devices with status {devices_response.status_code}: {devices_response.text}")
                return []

            return devices_response.json()

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return []

    def process_devices(self, devices):
        missing_devices = [device['name'] for device in devices if not self.check_device_exists(device['ipAddress'])]
        num_missing = len(missing_devices)
        if num_missing:
            logger.info(f"Total {num_missing} devices processed and identified for onboarding.")
            return f"Total {num_missing} devices missing from Nautobot and identified for onboarding: {', '.join(missing_devices)}"
        else:
            logger.info("No new devices needed onboarding.")
            return "All devices are already in Nautobot."

    def check_device_exists(self, ip):
        query = """
        query GetDeviceByIP($ip: [String]!) {
          ip_addresses(address: $ip) {
            address
            interface_assignments {
              interface {
                device {
                  name
                }
              }
            }
          }
        }
        """
        result = GraphQLQuery(query=query, variables={'ip': [ip]}).execute()
        return bool(result.get('data', {}).get('ip_addresses', []))

register_jobs(Sevone_Onboarding)
