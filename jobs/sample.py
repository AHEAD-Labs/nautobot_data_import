from nautobot.apps.jobs import Job, register_jobs
class Sample(Job):
    def run(self, data, commit):
        self.data = data
        self.commit = commit
        self.log_success(message='Job Ran')
register_jobs(Sample)