import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar, get_job
from nautobot.extras.models import GraphQLQuery, SecretsGroup, JobResult
from nautobot.dcim.models import Device, Location, LocationType, Manufacturer, DeviceType, Platform
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
    sevone_credentials = ObjectVar(
        model=SecretsGroup,
        description="SevOne API Credentials",
        required=True
    )
    additional_credentials = ObjectVar(
        model=SecretsGroup,
        description="Credentials for Device On Boarding",
        required=True
    )

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

    def onboard_device(self, device_name, device_ip, user):
        credentials_id = self.get_credentials_id()
        if not credentials_id:
            logger.error("Credentials ID not found. Check the provided credentials.")
            return
        logger.info(f"Checking if device '{device_name}' with IP '{device_ip}' exists in Nautobot.")

        # Check if the device already exists in Nautobot
        if self.device_exists_in_nautobot(device_name, device_ip):
            logger.info(f"Device {device_name} already exists in Nautobot. Skipping onboarding.")
            return

        # Ensure you have a Location object. Assuming 'Location' is already created and available
        # Here you'd typically fetch the location using some criteria or create it if it doesn't exist
        location = Location.objects.filter(name="Default Location").first()
        if not location:
            logger.error("Default location not found.")
            return

        # Fetching credentials ID
        credentials_id = self.get_credentials_id(
            'Default Credentials')  # Ensure this function is defined to fetch credentials
        if not credentials_id:
            logger.error("Credentials not found. Aborting onboarding.")
            return

        # Look up the onboarding job class in Nautobot
        job_class = get_job(
            'nautobot_device_onboarding.jobs.PerformDeviceOnboarding')  # Adjust the job identifier as needed
        if not job_class:
            logger.error("Onboarding job class not found. Please check the job identifier.")
            return

        # Prepare job data payload
        job_data = {
            'data': {
                'location': location.id,
                'ip_address': device_ip,
                'credentials': credentials_id,
                'port': "22",
                'timeout': "30",
            },
            'schedule': {
                'name': f"Onboarding {device_name}",
                'interval': 'immediately',
            },
            'task_queue': 'default'
        }

        # Create a JobResult to track the execution of the onboarding job
        job_result = JobResult.objects.create(
            name='Perform Device Onboarding',
            job_id='onboarding_job_identifier',  # Ensure correct identifier
            user=user,
            status='pending',
        )

        # Enqueue the onboarding job
        job_class.enqueue_job(
            data=job_data,
            user=user,
            commit=True,
            job_result=job_result,
        )

        logger.info(
            f"Onboarding job for device {device_name} with IP {device_ip} has been enqueued with job result ID: {job_result.pk}")

    def get_credentials_id(self):
        if self.additional_credentials:
            return self.additional_credentials.id
        return None

    def device_exists_in_nautobot(self, hostname, ip_address):
        try:
            # Ensure Device model is recognized and used for querying the database
            device_exists = Device.objects.filter(name=hostname).exists()
            ip_query = ip_address.split('/')[0]  # Assume IP address format includes a subnet mask
            ip_exists = IPAddress.objects.filter(address=ip_query).exists()
            return device_exists or ip_exists
        except Exception as e:
            logger.error(f"Error checking if device exists in Nautobot: {e}")
            return False


register_jobs(Sevone_Onboarding)
