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

    sevone_api_url = StringVar(
        description="URL of the SevOne API",
        default="http://gbsasev-pas01/"
    )

    sevone_credentials = ObjectVar(
        model=SecretsGroup,
        description="SevOne API Credentials"
    )

    def run(self, sevone_api_url, sevone_credentials):
        logger.info("Starting device onboarding process.")
        try:
            devices = self.fetch_devices_from_sevone(sevone_api_url, sevone_credentials)
            if devices:
                return self.process_devices(devices)
            else:
                logger.info("No devices fetched from SevOne.")
                return "No devices were found."
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}", extra={"grouping": "error", "object": self.job_result})
            raise Exception(f"An error occurred: {str(e)}")

    def fetch_devices_from_sevone(self, sevone_api_url, sevone_credentials):
        """Fetch devices from SevOne API using credentials from a secret."""
        logger.info(sevone_credentials)
        secrets_group = SecretsGroup.objects.get(name=sevone_credentials)

        try:
            username = secrets_group.get_secret_value(access_type='HTTP(S)', secret_type='Username')
            password = secrets_group.get_secret_value(access_type='HTTP(S)', secret_type='Password')

            creds = {'name': username, 'password': password}
            auth_response = requests.post(f"{sevone_api_url}/authentication/signin", json=creds,
                                          headers={'Content-Type': 'application/json'})
            if auth_response.status_code != 200:
                logger.error("Authentication failed!")
                return []

            token = auth_response.json()['token']
            session = requests.Session()
            session.headers.update({'Content-Type': 'application/json', 'X-AUTH-TOKEN': token})

            devices_response = session.get(f"{sevone_api_url}/devices?page=0&size=10000")
            if devices_response.status_code != 200:
                logger.error("Failed to fetch devices!")
                return []

            return devices_response.json()

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return []

    def process_devices(self, devices):
        """Process each device and determine if it's missing from Nautobot."""
        missing_devices = []
        for device in devices:
            if not self.check_device_exists(device['ipAddress']):
                missing_devices.append(device['name'])

        num_missing = len(missing_devices)
        if num_missing:
            logger.info(f"Total {num_missing} devices processed and identified for onboarding.")
            return f"Total {num_missing} devices missing from Nautobot and identified for onboarding: {', '.join(missing_devices)}"
        else:
            logger.info("No new devices needed onboarding.")
            return "All devices are already in Nautobot."

    def check_device_exists(self, ip):
        """Check if a device with the given IP address exists in Nautobot using GraphQL."""
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
        variables = {'ip': [ip]}
        result = GraphQLQuery(query=query, variables=variables).execute()
        data = result.get('data', {}).get('ip_addresses', [])
        return bool(data)

register_jobs(Sevone_Onboarding)
