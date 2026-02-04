"""
Metrics Collector for tracking bot performance over time
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """A single metric data point"""
    timestamp: datetime
    metric: str
    value: float
    tags: Dict[str, str]

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'metric': self.metric,
            'value': self.value,
            'tags': self.tags
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'MetricPoint':
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp']),
            metric=data['metric'],
            value=data['value'],
            tags=data.get('tags', {})
        )


class MetricsCollector:
    """Collects and aggregates bot metrics over time"""

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = data_dir
        self.metrics_file = os.path.join(data_dir, "metrics.jsonl")
        os.makedirs(data_dir, exist_ok=True)

    def record(self, metric: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record a metric data point"""
        point = MetricPoint(
            timestamp=datetime.now(),
            metric=metric,
            value=value,
            tags=tags or {}
        )

        try:
            with open(self.metrics_file, 'a') as f:
                f.write(json.dumps(point.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to record metric: {e}")

    def load_metrics(
        self,
        metric_name: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 10000
    ) -> List[MetricPoint]:
        """Load metrics from disk"""
        metrics = []
        if not os.path.exists(self.metrics_file):
            return metrics

        try:
            with open(self.metrics_file, 'r') as f:
                for line in f:
                    if line.strip():
                        point = MetricPoint.from_dict(json.loads(line))
                        if metric_name and point.metric != metric_name:
                            continue
                        if since and point.timestamp < since:
                            continue
                        metrics.append(point)

            return metrics[-limit:]
        except Exception as e:
            logger.error(f"Failed to load metrics: {e}")
            return []

    def get_time_series(
        self,
        metric_name: str,
        since: Optional[datetime] = None,
        interval: str = 'hour'
    ) -> List[Dict[str, Any]]:
        """Get aggregated time series data for a metric"""
        metrics = self.load_metrics(metric_name, since)

        if not metrics:
            return []

        # Group by interval
        grouped = defaultdict(list)
        for point in metrics:
            if interval == 'hour':
                key = point.timestamp.replace(minute=0, second=0, microsecond=0)
            elif interval == 'day':
                key = point.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            else:  # minute
                key = point.timestamp.replace(second=0, microsecond=0)

            grouped[key].append(point.value)

        # Aggregate
        result = []
        for timestamp, values in sorted(grouped.items()):
            result.append({
                'timestamp': timestamp.isoformat(),
                'avg': sum(values) / len(values),
                'min': min(values),
                'max': max(values),
                'count': len(values),
                'sum': sum(values)
            })

        return result

    def get_summary(self, since: Optional[datetime] = None) -> Dict[str, Any]:
        """Get summary statistics for all metrics"""
        metrics = self.load_metrics(since=since)

        if not metrics:
            return {}

        by_name = defaultdict(list)
        for point in metrics:
            by_name[point.metric].append(point.value)

        summary = {}
        for name, values in by_name.items():
            summary[name] = {
                'avg': sum(values) / len(values),
                'min': min(values),
                'max': max(values),
                'count': len(values),
                'total': sum(values),
                'latest': values[-1] if values else None
            }

        return summary

    def get_engagement_trends(self, days: int = 7) -> Dict[str, Any]:
        """Get engagement trends over the past N days"""
        since = datetime.now() - timedelta(days=days)
        metrics = self.load_metrics(since=since)

        daily_upvotes = defaultdict(int)
        daily_comments = defaultdict(int)
        daily_posts = defaultdict(int)

        for point in metrics:
            day = point.timestamp.strftime('%Y-%m-%d')
            if point.metric == 'upvotes':
                daily_upvotes[day] += point.value
            elif point.metric == 'comments':
                daily_comments[day] += point.value
            elif point.metric == 'posts':
                daily_posts[day] += point.value

        return {
            'upvotes_by_day': dict(daily_upvotes),
            'comments_by_day': dict(daily_comments),
            'posts_by_day': dict(daily_posts)
        }

    def get_community_breakdown(self) -> Dict[str, Dict[str, int]]:
        """Get activity breakdown by community"""
        metrics = self.load_metrics()

        breakdown = defaultdict(lambda: {'posts': 0, 'comments': 0, 'upvotes': 0})

        for point in metrics:
            community = point.tags.get('community', 'unknown')
            if point.metric == 'post':
                breakdown[community]['posts'] += 1
            elif point.metric == 'comment':
                breakdown[community]['comments'] += 1
            elif point.metric == 'upvotes':
                breakdown[community]['upvotes'] += int(point.value)

        return dict(breakdown)
