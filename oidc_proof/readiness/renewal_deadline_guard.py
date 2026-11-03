"""Offline proposal guard only. Does not authenticate, configure or grant access.

Inputs are trusted planner values, not tool or peer instructions. Integer Unix
seconds only; the calling workflow must independently verify provider behavior,
current settings, exact owner approval and the actual initial issuance time.
"""
from dataclasses import dataclass

PILOT_CUTOFF = 1793967840


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'{name} must be an integer >= {minimum}')
    return value


@dataclass(frozen=True)
class RenewalWindow:
    earliest_issuance: int
    latest_issuance: int
    maximum_lifetime: int
    idle_lifetime: int
    margin: int
    duration_step: int

    def validate_issuance(self, issued_at):
        """Recheck the fixed proposal at issuance; never slide the deadline."""
        integer(issued_at, 'issued_at')
        integer(self.maximum_lifetime, 'maximum_lifetime', 1)
        integer(self.idle_lifetime, 'idle_lifetime', 1)
        # Validate every field again, including manually constructed instances.
        expected = propose_window(self.earliest_issuance, self.latest_issuance,
                                  margin=self.margin,
                                  duration_step=self.duration_step)
        if self != expected:
            raise ValueError('proposal differs from the bounded policy')
        if not self.earliest_issuance <= issued_at <= self.latest_issuance:
            raise ValueError('issuance outside the approved proposal window')
        return issued_at + self.maximum_lifetime


def propose_window(earliest_issuance, latest_issuance, *, margin=60, duration_step=1):
    """Compute a candidate, never an approval. Cutoff is deliberately immutable.

    Round maximum and idle down to a provider-supported whole-second step.
    A provider minimum must be checked separately; do not round upward to meet it.
    """
    integer(earliest_issuance, 'earliest_issuance')
    integer(latest_issuance, 'latest_issuance')
    integer(margin, 'margin', 1)
    integer(duration_step, 'duration_step', 1)
    if earliest_issuance > latest_issuance:
        raise ValueError('reversed issuance window')
    budget = PILOT_CUTOFF - latest_issuance - margin
    maximum = (budget // duration_step) * duration_step
    idle = (min(86400, maximum) // duration_step) * duration_step
    if maximum <= 0 or idle <= 0:
        raise ValueError('no positive provider-compatible lifetime remains')
    return RenewalWindow(earliest_issuance, latest_issuance, maximum, idle,
                         margin, duration_step)
