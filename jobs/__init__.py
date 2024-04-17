from nautobot.apps.jobs import Job, register_jobs
from .sample import Sample
register_jobs(Sample)