import requests
from celery.utils.log import get_task_logger
from nautobot.apps.jobs import Job, register_jobs
from nautobot.extras.jobs import StringVar, ObjectVar, get_job
from nautobot.extras.models import JobResult, SecretsGroup
from nautobot.dcim.models import Device, Location, Manufacturer, DeviceType, Platform, LocationType
from nautobot.ipam.models import IPAddress
from nautobot.extras.models import Status, Role

# Setup the logger using Nautobot's get_task_logger function
logger = get_task_logger(__name__)

class Sevone_Onboarding(Job):
    class Meta:
        name = "Device Onboarding from SevOne"
        description = "Onboards devices from SevOne by fetching and processing their details."

    sevone_api_url = StringVar(description="URL of the SevOne API", default="http://gbsasev-pas01/api/v2/")
    sevone_credentials = ObjectVar(model=SecretsGroup, description="SevOne API Credentials", required=True)
    on_boarding_credentials = ObjectVar(model=SecretsGroup, description="Additional Credentials for Device Onboarding",
                                       required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = getattr(self, 'context', {})

    def run(self, sevone_api_url, sevone_credentials, on_boarding_credentials):
        logger.info("Starting device onboarding process.")
        devices = self.fetch_devices_from_sevone(sevone_api_url, sevone_credentials)
        if devices and isinstance(devices, list):
            self.process_devices(devices, on_boarding_credentials)
        else:
            logger.warning("Unexpected devices data type or empty list received.")

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
            if not self.device_exists_in_nautobot(device_name, device_ip):
                credentials_id = self.get_credentials_id(additional_credentials)
                if credentials_id:
                    location_id = self.configure_location(device_name)
                    self.run_onboarding_job(device_name, device_ip, credentials_id, location_id)
                else:
                    logger.error("Credentials ID not found. Check the provided credentials.")

    def run_onboarding_job(self, device_name, device_ip, credentials_id, location_id):
        logger.info(f"Preparing to onboard device: {device_name} at IP: {device_ip}")
        job_class = get_job('nautobot_device_onboarding.jobs.OnboardingTask')

        if not job_class:
            logger.error("Onboarding job class not found. Check the job configuration.")
            return

        try:
            # Fetch the actual SecretsGroup object using credentials_id
            credentials_object = SecretsGroup.objects.get(id=credentials_id)
        except SecretsGroup.DoesNotExist:
            logger.error(f"Credentials with ID {credentials_id} not found.")
            return
        except Exception as e:
            logger.error(f"Error retrieving credentials: {str(e)}")
            return

        logger.debug(f"Location ID: {location_id}, Device IP: {device_ip}, Credentials Object: {credentials_object}")

        job_data = {
            'location': location_id,
            'ip_address': device_ip,
            'credentials': credentials_id,
            'port': 22,
            'timeout': 30,
        }

        try:
            job_instance = job_class()
            job_instance.run(data=job_data, commit=True)
            logger.info(f"Onboarding job executed successfully for {device_name} with IP {device_ip}.")
        except Exception as e:
            logger.error(f"Error executing onboarding job for {device_name}: {str(e)}")
            logger.debug(f"Job data provided: {job_data}")

    def get_credentials_id(self, on_boarding_credentials):
        # Assuming additional_credentials is a SecretsGroup object from which we can get an ID directly
        try:
            logger.info(f"Getting credentials {on_boarding_credentials} with ID {on_boarding_credentials.id}")
            return on_boarding_credentials.id
        except Exception as e:
            logger.error(f"Failed to retrieve credentials ID: {str(e)}")
            return None

    def device_exists_in_nautobot(self, hostname, ip_address):
        try:
            device_exists = Device.objects.filter(name=hostname).exists()
            ip_query = ip_address.split('/')[0]
            ip_exists = IPAddress.objects.filter(address=ip_query).exists()

            # Adding detailed logging for clarity on what is being checked and the results
            logger.info(
                f"Checking if device with hostname '{hostname}' exists in Nautobot: {'found' if device_exists else 'not found'}")
            logger.info(
                f"Checking if IP address '{ip_query}' exists in Nautobot: {'found' if ip_exists else 'not found'}")

            return device_exists or ip_exists
        except Exception as e:
            logger.error(f"Error checking if device exists in Nautobot: {e}")
            return False

    def configure_location(self, device_name):
        # Configure location based on device name
        location_code = device_name[:4].upper()
        try:
            location_type, location_type_created = LocationType.objects.get_or_create(name="Campus")
            if location_type_created:
                logger.info(f"Created new LocationType 'Campus'.")
            else:
                logger.info(f"Using existing LocationType 'Campus'.")

            status, status_created = Status.objects.get_or_create(name='Active', defaults={'slug': 'active'})
            if status_created:
                logger.info(f"Created new Status 'Active'.")
            else:
                logger.info(f"Using existing Status 'Active'.")

            location, created = Location.objects.get_or_create(
                name=location_code,
                defaults={'location_type': location_type, 'status': status}
            )
            if created:
                logger.info(f"Created new Location '{location_code}'.")
            else:
                logger.info(f"Using existing Location '{location_code}' with location id '{location.id}'.")

            return location.id

        except Exception as e:
            logger.error(f"Failed to configure location '{location_code}': {e}")
            return None  # Clearly return None in case of error

register_jobs(Sevone_Onboarding)