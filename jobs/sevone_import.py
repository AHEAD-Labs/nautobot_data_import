import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar
from nautobot.extras.models import GraphQLQuery, SecretsGroup
from nautobot.dcim.models import Device
from nautobot.ipam import IPAddress

# Setup the logger using Nautobot's get_task_logger function
logger = get_task_logger(__name__)

class Sevone_Onboarding(Job):
    class Meta:
        name = "Device Onboarding from SevOne"
        description = "Onboards devices from SevOne by fetching and processing their details."

    sevone_api_url = StringVar(description="URL of the SevOne API", default="http://gbsasev-pas01/api/v2/")
    sevone_credentials = ObjectVar(model=SecretsGroup, description="SevOne API Credentials")

    def run(self, sevone_api_url, sevone_credentials):
        logger.info("Starting device onboarding process.")
        devices = self.fetch_devices_from_sevone(sevone_api_url, sevone_credentials)
        if devices and isinstance(devices, list):
            return self.process_devices(devices)
        else:
            logger.warning("Unexpected devices data type or empty list received.")
            return "No devices were found."

    def fetch_devices_from_sevone(self, sevone_api_url, sevone_credentials):
        try:
            logger.info("Retrieving secrets for authentication.")
            username = sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='username')
            password = sevone_credentials.get_secret_value(access_type='HTTP(S)', secret_type='password')
            logger.info("Secrets retrieved successfully.")

            creds = {'name': username, 'password': password}
            logger.info(f"Sending authentication request to {sevone_api_url}authentication/signin")
            auth_response = requests.post(f"{sevone_api_url}authentication/signin", json=creds,
                                          headers={'Content-Type': 'application/json'})

            if auth_response.status_code != 200:
                logger.error(f"Authentication failed with status {auth_response.status_code}: {auth_response.text}")
                return []

            token = auth_response.json().get('token')
            logger.info("Authentication successful, token received.")

            session = requests.Session()
            session.headers.update({'Content-Type': 'application/json', 'X-AUTH-TOKEN': token})
            logger.info(f"Sending request to fetch devices from {sevone_api_url}devices?page=0&size=10000")
            devices_response = session.get(f"{sevone_api_url}devices?page=0&size=10000")

            if devices_response.status_code != 200:
                logger.error(
                    f"Failed to fetch devices with status {devices_response.status_code}: {devices_response.text}")
                return []

            devices = devices_response.json().get('content',
                                                  [])  # Ensure that 'content' key is the correct key that contains the devices list
            logger.info(f"Devices fetched successfully. Number of devices: {len(devices)}")
            logger.debug(
                f"Sample device data: {devices[0] if devices else 'No devices found'}")  # Log sample device data for verification

            return devices

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return []

    def process_devices(self, devices):
        missing_devices = []
        for device in devices:
            if not self.device_exists_in_nautobot(device['name'], device['ipAddress']):
                missing_devices.append(device['name'])

        num_missing = len(missing_devices)
        if num_missing:
            logger.info(f"Total {num_missing} devices processed and identified for onboarding.")
            return f"Total {num_missing} devices missing from Nautobot and identified for onboarding: {', '.join(missing_devices)}"
        else:
            logger.info("No new devices needed onboarding.")
            return "All devices are already in Nautobot."

    def device_exists_in_nautobot(self, hostname, ip):
        # Check if a device with the given hostname or IP exists in Nautobot
        device_exists = Device.objects.filter(name=hostname).exists()
        ip_exists = IPAddress.objects.filter(address__startswith=ip.split('/')[0]).exists()
        return device_exists or ip_exists

register_jobs(Sevone_Onboarding)
