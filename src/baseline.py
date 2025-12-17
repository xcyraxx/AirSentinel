import os
import json
import statistics

class Baseline:
    def __init__(self):
        self.samples = []

    def update(self, features):
        self.samples.append(features)
        if len(self.samples) > 50:
            self.samples.pop(0)

    def ready(self):
        return len(self.samples) >= 3

    def stats(self):
        mean = statistics.median(f["mean_interval"] for f in self.samples)
        jitter = sum(f["jitter"] for f in self.samples) / len(self.samples)
        return mean, jitter
    
    @staticmethod
    def load(path):
        with open(path) as f:
            return json.load(f)

class CUSUM:
    def __init__(self, k=0.01, h=0.05):
        self.S = 0.0
        self.k = k  # slack (normal drift)
        self.h = h  # alert threshold

    def update(self, delta):
        # accumulate only meaningful drift
        self.S = max(0.0, self.S + delta - self.k)

        if self.S >= self.h:
            self.S = 0.0  # reset after alert
            return True

        return False
