from zapper.lang.contract import Contract, constructor
from zapper.lang.type_address import Address
from zapper.lang.types import Uint, Long
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime

# META-NAME Reviews
# META-DESC A double-blind peer-review system for academic papers.


class Review(Contract):

    reviewer: Address
    pc: Address
    paper_id: Long
    score: Uint

    @constructor
    def create(self, reviewer: Address, paper_id: Long):
        self.owner = reviewer
        self.reviewer = reviewer
        self.paper_id = paper_id
        self.score = 0
        self.pc = self.me

    def set_score(self, score: Uint):
        self.require(self.reviewer == self.me)
        self.require(self.score == 0)
        self.require(1 <= score <= 5)
        self.score = score
        self.owner = self.pc

    def incorporate(self) -> Uint:
        self.require(self.pc == self.me)
        score = self.score
        self.kill()
        return score


class Result(Contract):

    author: Address
    pc: Address
    paper_id: Long
    total_score: Uint
    accepted: Uint

    @constructor
    def create(self, author: Address, paper_id: Long):
        self.owner = self.me
        self.author = author
        self.paper_id = paper_id
        self.total_score = 0
        self.accepted = 0
        self.pc = self.me

    def increase_score(self, diff: Uint):
        self.require(self.pc == self.me)
        self.total_score += diff

    def notify_author(self, accepted: Uint):
        self.require(self.pc == self.me)
        self.accepted = accepted
        self.owner = self.author


class Paper(Contract):

    author: Address
    paper_id: Long
    result: Result

    @constructor
    def create(self, author: Address):
        self.owner = self.me    # program chair
        self.author = author
        self.paper_id = self.fresh()
        self.result = self.create_new_object(Result.create, author, self.paper_id)

    def request_review(self, reviewer: Address) -> Review:
        return self.create_new_object(Review.create, reviewer, self.paper_id)

    def incorporate_review(self, review: Review):
        self.require(review.paper_id == self.paper_id)
        self.result.increase_score(review.incorporate())

    def notify_author(self, accepted: Uint):
        self.result.notify_author(accepted)


def run_reviews(ledger: Ledger):
    runtime = Runtime(ledger)
    pc = runtime.new_user_account()
    author = runtime.new_user_account()
    reviewer_1 = runtime.new_user_account()
    reviewer_2 = runtime.new_user_account()

    paper = runtime.get_class_handle(Paper).create(author.address, sender=pc)
    review_1 = paper.request_review(reviewer_1.address, sender=pc)
    review_2 = paper.request_review(reviewer_2.address, sender=pc)
    review_1.set_score(4, sender=reviewer_1)
    review_2.set_score(3, sender=reviewer_2)
    paper.incorporate_review(review_1, sender=pc)
    paper.incorporate_review(review_2, sender=pc)
    paper.notify_author(1, sender=pc)

    result = paper.result
    assert(result.owner == author.address)
    assert(result.total_score == 7)
    assert(result.accepted == 1)
