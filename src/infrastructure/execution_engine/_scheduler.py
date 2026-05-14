"""DAG scheduler extracted from concurrent_executor.

Provides the _DAGScheduler class which resolves task dependencies into
executable layers via topological sort. This keeps scheduling logic
separated for easier maintenance.
"""

import logging

from src.infrastructure.execution_engine.models import Task

logger = logging.getLogger(__name__)


class _DAGScheduler:
    """Resolves task dependencies into executable layers via topological sort.

    Tasks with no unmet dependencies are grouped into the same layer and can
    therefore be executed in parallel.
    """

    def __init__(self, tasks: list[Task]) -> None:
        self._tasks: dict[str, Task] = {t.id: t for t in tasks}
        self._all_ids = set(self._tasks.keys())

    def validate(self) -> list[str]:
        """Validate the DAG and return any cycle warnings.

        Returns:
            List of warning messages (empty if valid).
        """
        warnings: list[str] = []
        for task in self._tasks.values():
            for dep_id in task.dependencies:
                if dep_id not in self._all_ids:
                    warnings.append(
                        f"Task '{task.name}' ({task.id}) depends on unknown task '{dep_id}'"
                    )

        if self._detect_cycle():
            warnings.append("Dependency cycle detected in task graph")

        return warnings

    def _detect_cycle(self) -> bool:
        visited: set[str] = set()
        in_stack: set[str] = set()

        def _dfs(task_id: str) -> bool:
            visited.add(task_id)
            in_stack.add(task_id)
            task = self._tasks.get(task_id)
            if task:
                for dep_id in task.dependencies:
                    if dep_id in self._all_ids:
                        if dep_id not in visited:
                            if _dfs(dep_id):
                                return True
                        elif dep_id in in_stack:
                            return True
            in_stack.discard(task_id)
            return False

        for task_id in self._all_ids:
            if task_id not in visited:
                if _dfs(task_id):
                    return True
        return False

    def get_layers(self) -> list[list[Task]]:
        """Return tasks grouped into dependency-respecting layers.

        Each layer contains tasks whose dependencies are all satisfied by
        previous layers. Tasks within a layer can run in parallel.

        Returns:
            List of layers, each containing a list of Task objects.
        """
        in_degree: dict[str, int] = {tid: 0 for tid in self._all_ids}
        dependents: dict[str, set[str]] = {tid: set() for tid in self._all_ids}

        for task in self._tasks.values():
            for dep_id in task.dependencies:
                if dep_id in self._all_ids:
                    in_degree[task.id] += 1
                    dependents[dep_id].add(task.id)

        queue = [tid for tid, degree in in_degree.items() if degree == 0]
        queue.sort(key=lambda tid: self._tasks[tid].priority.value)

        layers: list[list[Task]] = []
        executed: set[str] = set()

        while queue:
            layer_tasks = [self._tasks[tid] for tid in queue]
            layer_tasks.sort(key=lambda t: (t.priority.value, t.name))
            layers.append(layer_tasks)
            executed.update(queue)

            next_queue: list[str] = []
            for tid in queue:
                for dependent_id in dependents[tid]:
                    in_degree[dependent_id] -= 1
                    if in_degree[dependent_id] == 0:
                        next_queue.append(dependent_id)

            next_queue.sort(key=lambda tid: self._tasks[tid].priority.value)
            queue = next_queue

        remaining = self._all_ids - executed
        if remaining:
            remaining_tasks = [self._tasks[tid] for tid in remaining]
            remaining_tasks.sort(key=lambda t: (t.priority.value, t.name))
            layers.append(remaining_tasks)
            logger.warning("Tasks with unresolvable dependencies: %s", remaining)

        return layers
