from tests.test_integration_modules import _make_session, VulnAppFixture
from scanner.modules import zero_day

class Dummy(VulnAppFixture):
    def run(self):
        self.setUpClass()
        try:
            session = _make_session()
            zero_day.run(session)
        finally:
            self.tearDownClass()

if __name__ == "__main__":
    d = Dummy()
    d.run()
