import dataclasses
import unittest
from renewal_deadline_guard import PILOT_CUTOFF, propose_window


class DeadlineTests(unittest.TestCase):
    def test_historical_packet_example(self):
        plan = propose_window(1793617200, 1793620800)
        self.assertEqual(plan.maximum_lifetime, 346980)
        self.assertEqual(plan.idle_lifetime, 86400)
        self.assertEqual(plan.validate_issuance(plan.latest_issuance), PILOT_CUTOFF - 60)

    def test_stale_example_rejected(self):
        plan = propose_window(1793617200, 1793620800)
        with self.assertRaises(ValueError):
            plan.validate_issuance(1793707200)

    def test_window_boundaries(self):
        plan = propose_window(PILOT_CUTOFF - 1000, PILOT_CUTOFF - 500)
        for now in [plan.earliest_issuance, plan.latest_issuance]:
            self.assertLessEqual(plan.validate_issuance(now), PILOT_CUTOFF - 60)
        for now in [plan.earliest_issuance - 1, plan.latest_issuance + 1]:
            with self.assertRaises(ValueError): plan.validate_issuance(now)

    def test_deadline_boundary(self):
        self.assertEqual(propose_window(0, PILOT_CUTOFF - 61).maximum_lifetime, 1)
        for latest in [PILOT_CUTOFF - 60, PILOT_CUTOFF, PILOT_CUTOFF + 1]:
            with self.assertRaises(ValueError): propose_window(0, latest)

    def test_round_down(self):
        plan = propose_window(0, PILOT_CUTOFF - 1000, duration_step=60)
        self.assertEqual((plan.maximum_lifetime, plan.idle_lifetime), (900, 900))
        with self.assertRaises(ValueError):
            propose_window(0, PILOT_CUTOFF - 100, duration_step=60)

    def test_idle_step(self):
        plan = propose_window(0, PILOT_CUTOFF - 200000, duration_step=1000)
        self.assertEqual(plan.idle_lifetime, 86000)

    def test_reversed_window(self):
        with self.assertRaises(ValueError): propose_window(2, 1)

    def test_strict_input_types(self):
        for value in [True, False, 1.0, float('nan'), float('inf'), '123', None, -1]:
            for field in ['earliest', 'latest', 'margin', 'step']:
                args = dict(earliest_issuance=0, latest_issuance=PILOT_CUTOFF-1000,
                            margin=60, duration_step=1)
                args[{'earliest':'earliest_issuance', 'latest':'latest_issuance',
                      'margin':'margin', 'step':'duration_step'}[field]] = value
                with self.subTest(value=value, field=field), self.assertRaises(ValueError):
                    propose_window(**args)

    def test_zero_margin_or_step_rejected(self):
        for kwargs in [dict(margin=0), dict(duration_step=0)]:
            with self.assertRaises(ValueError): propose_window(0, 100, **kwargs)

    def test_tampered_plan_rejected(self):
        plan = propose_window(0, PILOT_CUTOFF-1000)
        for field in ['maximum_lifetime', 'idle_lifetime']:
            changed = dataclasses.replace(plan, **{field:getattr(plan, field)+1})
            with self.assertRaises(ValueError): changed.validate_issuance(0)

    def test_forged_equal_noninteger_duration_rejected(self):
        plan = propose_window(0, PILOT_CUTOFF-61)
        for field in ['maximum_lifetime', 'idle_lifetime']:
            for value in [True, 1.0]:
                changed = dataclasses.replace(plan, **{field:value})
                with self.assertRaises(ValueError): changed.validate_issuance(0)

    def test_issuance_types(self):
        plan = propose_window(0, PILOT_CUTOFF-1000)
        for value in [True, 0.0, None, -1]:
            with self.assertRaises(ValueError): plan.validate_issuance(value)

    def test_many_windows_preserve_invariant(self):
        for remaining in range(61, 200000, 997):
            for step in [1, 60, 1000]:
                latest = PILOT_CUTOFF-remaining
                try: plan = propose_window(latest-300, latest, duration_step=step)
                except ValueError:
                    self.assertLess(min(remaining-60, 86400), step)
                    continue
                for issued in [latest-300, latest-1, latest]:
                    self.assertLessEqual(plan.validate_issuance(issued), PILOT_CUTOFF-60)
                self.assertTrue(0 < plan.idle_lifetime <= min(86400,plan.maximum_lifetime))
                self.assertEqual(plan.maximum_lifetime % step, 0)


if __name__ == '__main__': unittest.main()
