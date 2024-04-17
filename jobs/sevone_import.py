import logging
import requests
from nautobot.extras.models import GraphQLQuery, SecretsGroup
from nautobot.apps.jobs import Job, StringVar, ObjectVar, register_jobs

logger = logging.getLogger("nautobot.jobs.Sevone_Onboarding")

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
        description="SevOne API Credentials",
        display_field='name',
        default="SEVONE"
    )

    def run(self, data, commit):
        logger.info("Starting device onboarding process.")
        try:
            devices = self.fetch_devices_from_sevone()
            if devices:
                return self.process_devices(devices)
            else:
                logger.info("No devices fetched from SevOne.")
                return "No devices were found."
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return f"An error occurred: {str(e)}"

    def fetch_devices_from_sevone(self):
        """Fetch devices from SevOne API using credentials from a secret."""
        try:
            username = self.sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='Username')
            password = self.sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='Password')

            creds = {'name': username, 'password': password}
            auth_response = requests.post(f"{self.sevone_api_url}/authentication/signin", json=creds,
                                          headers={'Content-Type': 'application/json'})

            if auth_response.status_code != 200:
                logger.error("Authentication failed!")
                return []

            token = auth_response.json()['token']
            session = requests.Session()
            session.headers.update({'Content-Type': 'application/json', 'X-AUTH-TOKEN': token})

            devices_response = session.get(f"{self.sevone_api_url}/devices?page=0&size=10000")
            if devices_response.status_code != 200:
                logger.error("Failed to fetch devices!")
                return []

            return devices_response.json()['content']

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return []

    def process_devices(self, devices):
        """Process each device and determine if it's missing from Nautobot."""
        missing_devices = []
        for device in devices:
            if not self.check_device_exists(device['ipAddress']):
                missing_devices.append(device)

        num_devices = len(missing_devices)
        logger.info(f"{num_devices} devices are missing and will be onboarded.")
        # Optionally, add details about the devices processed
        details = "\n".join([f"Device: {device['name']}, IP: {device['ipAddress']}" for device in missing_devices])
        return f"Total {num_devices} devices processed and identified for onboarding.\nDetails:\n{details}"

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

        if data:
            return True
        return False

register_jobs(Sevone_Onboarding)
