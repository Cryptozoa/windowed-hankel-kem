"""The existing canonical Windowed Hankel KEM wire profile."""

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class HankelParameters:
    """Frozen parameters for the one currently supported wire profile."""

    n: int = 640
    w: int = 128
    q: int = 4096
    eta: int = 2

    def __post_init__(self) -> None:
        values = (self.n, self.w, self.q, self.eta)
        if any(type(value) is not int for value in values) or values != (640, 128, 4096, 2):
            raise ValueError("Only the canonical n=640, w=128, q=4096, eta=2 wire profile is supported")

    @property
    def m_len(self) -> int:
        return self.n + self.w

    @property
    def total_a_len(self) -> int:
        return 2 * self.n + self.w - 1

    @property
    def q_mask(self) -> int:
        return self.q - 1

    @property
    def pam_points(self) -> tuple[int, int, int, int]:
        return (0, self.q // 4, self.q // 2, 3 * self.q // 4)

    @property
    def decision_threshold(self) -> int:
        return self.q // 8

    @property
    def pk_bytes(self) -> int:
        return 12 + 32 + (self.m_len * 3) // 2

    @property
    def ct_bytes(self) -> int:
        return 12 + ((self.m_len + self.w) * 3) // 2

    @property
    def sk_bytes(self) -> int:
        return self.n + 32 + self.pk_bytes


CANONICAL = HankelParameters()

Q = CANONICAL.q
Q_MASK = CANONICAL.q_mask
ETA = CANONICAL.eta
N = CANONICAL.n
W = CANONICAL.w
M_LEN = CANONICAL.m_len
TOTAL_A_LEN = CANONICAL.total_a_len
PAM_POINTS = np.array(CANONICAL.pam_points, dtype=np.int64)
DECISION_THRESHOLD = CANONICAL.decision_threshold
PK_BYTES = CANONICAL.pk_bytes
CT_BYTES = CANONICAL.ct_bytes
SK_BYTES = CANONICAL.sk_bytes
