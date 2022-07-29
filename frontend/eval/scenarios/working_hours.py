from zapper.lang.contract import Contract, constructor, only
from zapper.lang.type_address import Address
from zapper.lang.types import Uint, Long, AddressConst
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime, Account

# to be set _after_ parameter generation, but before compilation
EMPLOYER_ACCOUNT: Account = None

# META-NAME WorkLog
# META-DESC A system for aggregate working hours reports hiding check-in/-out times.


class Aggregated(Contract):

    employee: Address
    total_time: Uint

    @only("eval.scenarios.working_hours.WorkLog")
    @constructor
    def create(self, total_time: Uint):
        self.employee = self.me
        self.total_time = total_time
        self.owner = AddressConst(EMPLOYER_ACCOUNT.address)


class WorkLog(Contract):

    total_time: Uint
    start_time: Uint
    is_working: Uint

    @constructor
    def create(self):
        self.total_time = 0
        self.start_time = 0
        self.is_working = 0
        self.owner = self.me

    def start_work(self):
        self.require(self.is_working == 0)
        self.start_time = self.now()
        self.is_working = 1

    def end_work(self):
        self.require(self.is_working == 1)
        time_worked = self.now() - self.start_time
        self.total_time = self.total_time + time_worked
        self.is_working = 0

    def prove_to_employer(self) -> Aggregated:
        self.require(self.total_time >= 10)
        aggregated = self.create_new_object(Aggregated.create, self.total_time)
        self.total_time = 0
        return aggregated


def run_working_hours(ledger: Ledger):
    runtime = Runtime(ledger)
    employee = runtime.new_user_account()

    # use hardcoded employer
    employer = EMPLOYER_ACCOUNT
    runtime.register_account(employer)

    log = runtime.get_class_handle(WorkLog).create(sender=employee)
    log.start_work(sender=employee)
    ledger.test_increase_current_time_by(17)
    log.end_work(sender=employee)
    aggregated = log.prove_to_employer(sender=employee)

    assert(aggregated.owner == employer.address)
    assert(aggregated.employee == employee.address)
    assert(aggregated.total_time == 17)
