import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar, get_job
from nautobot.extras.models import JobResult, SecretsGroup
from nautobot.dcim.models import Device, Location, Manufacturer, DeviceType, Platform, LocationType
from nautobot.ipam.models import IPAddress
from nautobot.tenancy.models import Tenant
from nautobot.extras.models import Status, Role
from django.db import transaction
from django.utils.text import slugify
from django.contrib.auth import get_user_model

# Setup the logger using Nautobot's get_task_logger function
logger = get_task_logger(__name__)


class Sevone_Onboarding(Job):
    class Meta:
        name = "Device Onboarding from SevOne"
        description = "Onboards devices from SevOne by fetching and processing their details."

    sevone_api_url = StringVar(description="URL of the SevOne API", default="http://gbsasev-pas01/api/v2/")
    sevone_credentials = ObjectVar(model=SecretsGroup, description="SevOne API Credentials", required=True)
    additional_credentials = ObjectVar(model=SecretsGroup, description="Additional Credentials for Device Onboarding",
                                       required=True)

    def run(self, sevone_api_url, sevone_credentials, additional_credentials):
        logger.info("Starting device onboarding process.")
        devices = self.fetch_devices_from_sevone(sevone_api_url, sevone_credentials)
        if devices and isinstance(devices, list):
            return self.process_devices(devices, additional_credentials)
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

            devices = devices_response.json().get('content', [])
            logger.info(f"Devices fetched successfully. Number of devices: {len(devices)}")
            return devices
        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return []

    def process_devices(self, devices, additional_credentials):
        for device_data in devices:
            device_name = device_data['name']
            device_ip = device_data['ipAddress']
            self.onboard_device(device_name, device_ip, additional_credentials)

    def onboard_device(self, device_name, device_ip, additional_credentials):
        # Extracting the location code from the device name
        location_code = device_name[:4].upper()
        location_slug = slugify(location_code)

        # Ensure LocationType exists
        location_type, lt_created = LocationType.objects.get_or_create(
            name="Campus",  # Example type name, adjust as needed
            defaults={'slug': slugify("Campus")}  # Assuming 'slug' is required here
        )
        if lt_created:
            logger.info(f"Created new LocationType: 'Campus'")
        else:
            logger.info(f"Using existing LocationType: 'Campus'")

        # Ensure Location exists
        location, loc_created = Location.objects.get_or_create(
            name=location_code,
            defaults={
                'slug': location_slug,
                'location_type': location_type
            }
        )
        if loc_created:
            logger.info(f"Created new location: {location_code}")
        else:
            logger.info(f"Using existing location: {location_code}")

        # Check if the device already exists
        if self.device_exists_in_nautobot(device_name, device_ip):
            logger.info(f"Device {device_name} already exists in Nautobot. Skipping onboarding.")
            return

        # Here goes the onboarding job invocation
        logger.info(f"Proceeding with onboarding for {device_name}.")

    def get_credentials_id(self, additional_credentials):
        return additional_credentials.id if additional_credentials else None

    def device_exists_in_nautobot(self, hostname, ip_address):
        try:
            device_exists = Device.objects.filter(name=hostname).exists()
            ip_query = ip_address.split('/')[0]
            ip_exists = IPAddress.objects.filter(address=ip_query).exists()
            return device_exists or ip_exists
        except Exception as e:
            logger.error(f"Error checking if device exists in Nautobot: {e}")
            return False


register_jobs(Sevone_Onboarding)
