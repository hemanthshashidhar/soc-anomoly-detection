from collections import defaultdict, deque

class IdentityRiskTracker:
    def __init__(self, window_size=10):
        self.user_risk_history = defaultdict(lambda: deque(maxlen=window_size))

    def update(self, user_id, risk_score):
        self.user_risk_history[user_id].append(risk_score)

    def get_risk_trend(self, user_id):
        history = list(self.user_risk_history[user_id])
        if len(history) < 3:
            return "STABLE", history

        if history[-1] > history[-2] > history[-3]:
            return "ESCALATING", history

        if history[-1] < history[-2]:
            return "DECREASING", history

        return "STABLE", history

    def is_under_active_attack(self, user_id):
        history = self.user_risk_history[user_id]
        if len(history) < 5:
            return False

        high_risk_events = sum(1 for r in history if r >= 70)
        return high_risk_events >= 3
