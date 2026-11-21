"""One-turn OpenEnv environment for an immutable authorization audit task."""

from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import Action, Observation, State

from .grading import parse_answer, payload_sha256, reward


class AuditAction(Action):
    submission: str


class AuditObservation(Observation):
    task_id: str
    prompt: str | None = None


class AuditEnvironment(Environment[AuditAction, AuditObservation, State]):
    def __init__(self, task: dict):
        if task["task_sha256"] != payload_sha256(task):
            raise ValueError("Task digest mismatch")
        self._task = task
        self._state = State()

    @property
    def state(self) -> State:
        return self._state

    def reset(self, seed=None, episode_id=None, **kwargs):
        self._state = State(episode_id=episode_id or str(uuid4()), step_count=0)
        return AuditObservation(task_id=self._task["task_id"], prompt=self._task["prompt"])

    def step(self, action: AuditAction, timeout_s=None, **kwargs):
        if self.state.episode_id is None or self.state.step_count != 0:
            raise RuntimeError("Reset the environment before submitting an answer")
        self._state.step_count = 1
        try:
            answer = parse_answer(action.submission)
        except (ValueError, RecursionError):
            answer = None
        return AuditObservation(task_id=self._task["task_id"], done=True,
                                reward=reward(self._task["answer"], answer))
