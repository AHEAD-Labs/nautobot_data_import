import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar, get_job
from nautobot.extras.models import GraphQLQuery, SecretsGroup, JobResult
from nautobot.dcim.models import Location, LocationType, Manufacturer, DeviceType, Platform
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
        logger.info(f"Attempting to onboard device: {device_name} with IP: {device_ip}")

        # Check if the device already exists in Nautobot
        if Device.objects.filter(name=device_name).exists():
            logger.info(f"Device {device_name} already exists in Nautobot.")
            return

        # Prepare the job parameters
        job_class = get_job('path.to.your.OnboardingJob')  # Update this path to the actual job class path
        if job_class is None:
            logger.error("Onboarding job class not found.")
            return

        # Define the job data
        job_data = {
            'device_name': device_name,
            'device_ip': device_ip,
            # Add additional parameters here as required
        }

        # Get admin user or any user as per your application's logic
        admin_user = get_user_model().objects.get(username='admin')  # Ensure the admin or a system user exists

        # Create a JobResult to track this job's execution
        job_result = JobResult.objects.create(
            name=job_class.class_path,
            job_id=job_class.class_path,
            user=admin_user,
            status='pending',
        )

        # Enqueue the job
        job_result.enqueue_job(
            run_job=job_class.function_name,  # This should be the callable function/method inside your job class
            data=job_data,
            request=self.request,
            user=admin_user,
            commit=True
        )

        logger.info(f"Onboarding job for {device_name} has been enqueued.")
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
