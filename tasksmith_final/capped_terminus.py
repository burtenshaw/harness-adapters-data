"""Terminus 2 with a hard aggregate token cap per attempt.

Before every turn the agent stops if the tokens already used, plus the current
context and the full output reservation, would exceed MAX_TOTAL_TOKENS. The loop
then ends normally, so the verifier still grades the workspace as it stands.
"""

from harbor.agents.terminus_2.terminus_2 import Terminus2

MAX_TOTAL_TOKENS = 2_000_000
MAX_OUTPUT_TOKENS = 65_536


class CappedTerminus2(Terminus2):
    @staticmethod
    def name() -> str:
        return "terminus-2-capped"

    async def _run_agent_loop(self, initial_prompt, chat, original_instruction=""):
        session = self._session
        alive = session.is_session_alive
        self.budget_stop = False

        async def within_budget():
            used = chat.total_input_tokens + chat.total_output_tokens
            if used + self._count_total_tokens(chat) + MAX_OUTPUT_TOKENS > MAX_TOTAL_TOKENS:
                self.budget_stop = True
                (self.logs_dir / "budget_stop.txt").write_text(f"{used}\n")
                return False
            return await alive()

        session.is_session_alive = within_budget
        return await super()._run_agent_loop(initial_prompt, chat, original_instruction)
