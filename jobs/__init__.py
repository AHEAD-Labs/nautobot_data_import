from nautobot.apps.jobs import Job, register_jobs
from .sevone_import import Sevone_Onboarding
register_jobs(Sevone_Onboarding)