import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar
from nautobot.extras.models import GraphQLQuery, SecretsGroup
from nautobot.dcim.models import Location, Manufacturer, DeviceType, Platform
from nautobot.ipam.models import IPAddress
from nautobot.tenancy.models import Tenant
from nautobot.extras.models import Status, Role
from django.db import transaction

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
        for device_data in devices:
            device_name = device_data['name']
            device_ip = device_data['ipAddress']
            # Call the new method to onboard the device
            self.onboard_device(device_name, device_ip)
    def onboard_device(self, device_name, device_ip):
        # Look up or create the necessary objects
        site, _ = Location.objects.get_or_create(name='Default Site', slug='default-site')
        manufacturer, _ = Manufacturer.objects.get_or_create(name='Default Manufacturer', slug='default-manufacturer')
        device_type, _ = DeviceType.objects.get_or_create(model='Default Device Type', manufacturer=manufacturer)
        device_role, _ = Role.objects.get_or_create(name='Default Role', slug='default-role')
        platform, _ = Platform.objects.get_or_create(name='Default Platform', slug='default-platform')
        status, _ = Status.objects.get_or_create(name='Active', slug='active')

        # Check if the device already exists
        if not Device.objects.filter(name=device_name).exists():
            # Start a new transaction
            with transaction.atomic():
                # Create the device if it doesn't exist
                device = Device.objects.create(
                    name=device_name,
                    device_type=device_type,
                    device_role=device_role,
                    platform=platform,
                    site=site,
                    status=status,
                )

                # Create an IPAddress object for the device's primary IP
                ip_address, created = IPAddress.objects.get_or_create(
                    address=device_ip,
                    defaults={
                        'status': status,
                        'tenant': Tenant.objects.get_or_create(name='Default Tenant', slug='default-tenant')[0],
                    },
                )
                if created:
                    logger.info(f"Created new IP address {device_ip} for device {device_name}.")
                else:
                    logger.info(f"IP address {device_ip} already existed.")

                # Assign the IP address to the device
                device.primary_ip4 = ip_address
                device.save()

                logger.info(f"Onboarded device {device_name} with IP {device_ip}.")
        else:
            logger.info(f"Device {device_name} already exists in Nautobot.")

    def device_exists_in_nautobot(self, hostname, ip_address):
        # Log the input hostname and IP address
        #logger.debug(f"Checking if device exists in Nautobot for hostname '{hostname}' and IP '{ip_address}'.")

        try:
            # Check if a device with the given hostname exists in Nautobot
            #logger.debug(f"Looking for device with hostname '{hostname}'.")
            device_exists = Device.objects.filter(name=hostname).exists()
            #logger.debug(f"Device with hostname '{hostname}' exists: {device_exists}")

            # Extract the IP address without the subnet mask
            ip_query = ip_address.split('/')[0]
            #logger.debug(f"Looking for IP address '{ip_query}'.")
            ip_exists = IPAddress.objects.filter(address=ip_query).exists()
            #logger.debug(f"IP address '{ip_query}' exists: {ip_exists}")

            return device_exists or ip_exists

        except Exception as e:
            # Log any exception that occurs during the check
            logger.error(f"Error checking if device exists in Nautobot: {e}")
            return False


register_jobs(Sevone_Onboarding)
