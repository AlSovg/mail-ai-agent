from mailagent.core.ratelimit import RateLimiter


def test_window_slides_and_users_are_independent():
    t = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: t[0])
    u1, u2 = ("max", "1"), ("max", "2")
    assert rl.allow(u1) and rl.allow(u1) and not rl.allow(u1)
    assert rl.allow(u2)  # чужой лимит не задет
    t[0] = 10.0
    assert rl.allow(u1)  # окно сдвинулось
