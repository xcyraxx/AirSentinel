import numpy as np

WINDOW = 10

def compute_features(timestamps):
    if len(timestamps) < 3:
        return None

    intervals = np.diff(timestamps)
    return {
        "mean_interval": float(intervals.mean()),
        "jitter": float(intervals.var()),
        "count": len(intervals)
    }
