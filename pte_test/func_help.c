




static __nocfi struct task_struct *get_task_by_pid(pid_t pid)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	return task;
}
