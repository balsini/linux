#ifndef _LINUX_SCHED_AB_H
#define _LINUX_SCHED_AB_H

#include <linux/sched.h>

#define MAX_AB_PRIO		(-10)

static inline int ab_prio(int prio)
{
	if (unlikely(prio < MAX_AB_PRIO))
		return 1;
	return 0;
}

static inline int ab_task(struct task_struct *p)
{
	return ab_prio(p->prio);
}

#endif /* _LINUX_SCHED_AB_H */
