from nautobot.apps.jobs import Job, register_jobs
from .sample import Sample
from .sevone_import import Sevone_Onboarding
register_jobs(Sample, Sevone_Onboarding)