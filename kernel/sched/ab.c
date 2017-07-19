#include "sched.h"
#include <uapi/linux/sched/types.h>

#define VERBOSE_DEBUG 0

/*****************************************************************************/
/* Utility functions to manage containers                                    */
/*****************************************************************************/

static inline struct task_struct *ab_task_of(struct sched_ab_entity *ab_se)
{
	return container_of(ab_se, struct task_struct, ab);
}

static inline struct ab_rq *ab_rq_of_se(struct sched_ab_entity *ab_se)
{
	struct task_struct *p = ab_task_of(ab_se);
	struct rq *rq = task_rq(p);

	return &rq->ab;
}

static inline struct rq *rq_of_ab_rq(struct ab_rq *ab_rq)
{
	return container_of(ab_rq, struct rq, ab);
}

/*****************************************************************************/
/* Utility functions for debugging                                           */
/*****************************************************************************/

#define DEBUG_PRINTK(string, args...) \
	do {\
	        if (VERBOSE_DEBUG)\
	                printk(KERN_DEBUG "SCHED_AB::"string, ##args);\
	} while (0)

static inline void decode_flags(int flags)
{
#if VERBOSE_DEBUG
	if (flags & ENQUEUE_WAKEUP)
		DEBUG_PRINTK("- ENQUEUE_WAKEUP");
	if (flags & ENQUEUE_RESTORE)
		DEBUG_PRINTK("- ENQUEUE_RESTORE");
	if (flags & ENQUEUE_MOVE)
		DEBUG_PRINTK("- ENQUEUE_MOVE");
	if (flags & ENQUEUE_NOCLOCK)
		DEBUG_PRINTK("- ENQUEUE_NOCLOCK");
	if (flags & ENQUEUE_HEAD)
		DEBUG_PRINTK("- ENQUEUE_HEAD");
	if (flags & ENQUEUE_REPLENISH)
		DEBUG_PRINTK("- ENQUEUE_REPLENISH");
	if (flags & ENQUEUE_MIGRATED)
		DEBUG_PRINTK("- ENQUEUE_MIGRATED");
#endif
}

static inline void print_tasks_in_ab_rq(struct ab_rq *ab_rq)
{
#if VERBOSE_DEBUG
	struct list_head *p;
	struct sched_ab_entity *ab_se;

	DEBUG_PRINTK("- CPU[%d] runnable_tasks[%d]",
	       cpu_of(rq_of_ab_rq(ab_rq)),
	       ab_rq->ab_nr_running);
	list_for_each(p, &ab_rq->runnable_tasks) {
		ab_se = list_entry(p, struct sched_ab_entity, runnable_elem);
		DEBUG_PRINTK("--- task[%d]", ab_task_of(ab_se)->pid);
	}
#endif
}

/****************************************************************************/
/*
 * Insert the task in the AB runnables queue (if not present).
 */
static inline void enqueue_ab_entity(struct sched_ab_entity *ab_se,
                                     unsigned int flags)
{
	struct ab_rq *ab_rq = ab_rq_of_se(ab_se);

	list_add_tail(&ab_se->runnable_elem, &ab_rq->runnable_tasks);
	ab_se->runnable = 1;
	++ab_rq->ab_nr_running;

	add_nr_running(rq_of_ab_rq(ab_rq), 1);
}

/*
 * Removes the task from the AB runnables queue (if present).
 */
static inline void dequeue_ab_entity(struct sched_ab_entity *ab_se)
{
	struct ab_rq *ab_rq = ab_rq_of_se(ab_se);
	
	list_del(&ab_se->runnable_elem);
	ab_se->runnable = 0;
	--ab_rq->ab_nr_running;

	sub_nr_running(rq_of_ab_rq(ab_rq), 1);
}

/*
 * The task moved to SCHED_AB.
 */
static void enqueue_task_ab(struct rq *rq,
			    struct task_struct *p,
			    int flags)
{
	struct sched_ab_entity *ab_se = &p->ab;

	DEBUG_PRINTK("%s task[%d] rq[%d] flags[%d]", __FUNCTION__,
	       p->pid, cpu_of(rq), flags);
	decode_flags(flags);
	
	/* Insert the task in one of the runqueues of AB, by using the proper
	 * helper funcion. */
	enqueue_ab_entity(ab_se, flags);

	print_tasks_in_ab_rq(&rq->ab);
}

/*
 * The task is no more runnable
 */
static void dequeue_task_ab(struct rq *rq,
			    struct task_struct *p,
			    int flags)
{
	struct sched_ab_entity *ab_se = &p->ab;

	DEBUG_PRINTK("%s task[%d] cpu[%d] flags[%d]", __FUNCTION__,
	       p->pid, cpu_of(rq), flags);
	decode_flags(flags);
	
	dequeue_ab_entity(ab_se);

	print_tasks_in_ab_rq(&rq->ab);
}

static void yield_task_ab(struct rq *rq)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

static void check_preempt_curr_ab(struct rq *rq,
				  struct task_struct *p,
				  int flags)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

static inline struct sched_ab_entity *pick_next_ab_entity(struct rq *rq,
                                                          struct ab_rq *ab_rq)
{
	return list_first_entry_or_null(&ab_rq->runnable_tasks,
					struct sched_ab_entity,
					runnable_elem);
}

/*
 * The scheduling_class is asked to return the highest priority task.
 * This because the current runqueue has completed its higher priority jobs and
 * is requesting for new workload.
 *
 * The parameter prev points to the current task in the runqueue, say the task
 * that is going to be substituted.
 */
static struct task_struct *pick_next_task_ab(struct rq *rq,
					     struct task_struct *prev,
					     struct rq_flags *rf)
{
	struct ab_rq *ab_rq = &rq->ab;
	struct sched_ab_entity *ab_se;
	struct task_struct *p;

	if (printk_ratelimit()) {
		DEBUG_PRINTK("%s rq[%d] prev[%d]",
		       __FUNCTION__, cpu_of(rq), prev->pid);
		print_tasks_in_ab_rq(&rq->ab);
	}

	/*
	 * It may happen that the function that the task that is going to be
	 * preempted could be used by its sched_class to update statistics or
	 *  may be enqueued as pushable. */
	if (prev->sched_class != &ab_sched_class)
		put_prev_task(rq, prev);

	/* We demand the choosing of the best task to be executed to a proper
	 * function. */
	ab_se = pick_next_ab_entity(rq, ab_rq);

	/* If there is no eligible task to be executed, then return NULL.
	 * the function caller will request to the next scheduling class for
	 * new tasks. */
	if (ab_se) {
		/* We found the candidate to be executed */
		DEBUG_PRINTK("%s - rq[%d] returning task[%d]", __FUNCTION__,
		       cpu_of(rq), ab_task_of(ab_se)->pid);

		p = ab_task_of(ab_se);

		return p;
	}

	return NULL;
}

static void put_prev_task_ab(struct rq *rq,
			     struct task_struct *p)
{
	DEBUG_PRINTK("%s task[%d]", __FUNCTION__, p->pid);
}

/*
 * Find the best runqueue for the given task.
 */
static int select_task_rq_ab(struct task_struct *p,
			     int cpu,
			     int sd_flag,
			     int flags)
{
	DEBUG_PRINTK("%s task[%d] cpu[%d] sd_flag[%d] flags[%d]",
	       __FUNCTION__, p->pid, cpu, sd_flag, flags);
	
	/* In this easiest configuration, the returned runqueue is the one
	 * passed as parameter (maybe we can take advantage of some still
	 * available cache data) */
	return cpu;
}

/*
 * Notification that the currently running task became a task of the SCHED_AB
 * class.
 * Notification that the currently running task is a task from SCHED_AB.
 */
static void set_curr_task_ab(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	
	DEBUG_PRINTK("%s, task[%d]", __FUNCTION__, p->pid);
}

/*
 * The given task has just woken up, then it is ready to run.
 */
static void task_woken_ab(struct rq *rq,
			  struct task_struct *p)
{
	DEBUG_PRINTK("%s task[%d]", __FUNCTION__, p->pid);
}

/*
 * The given task changed scheduling class to SCHED_AB.
 */
static void switched_to_ab(struct rq *rq,
			   struct task_struct *p)
{
	DEBUG_PRINTK("%s task[%d]", __FUNCTION__, p->pid);
}

/*
 * The given task left the SCHED_AB scheduling class.
 */
static void switched_from_ab(struct rq *rq,
			     struct task_struct *p)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

/*****************************************************************************/
/* Statistics management functions                                           */
/*****************************************************************************/

/*
 * This function is automatically called depending on the high-resolution
 * timer, with a frequency given by CONFIG_HZ.
 */
static void task_tick_ab(struct rq *rq,
			 struct task_struct *p,
			 int queued)
{
	//DEBUG_PRINTK("%s", __FUNCTION__);
}

/*
 * Update the current task's runtime statistics.
 * Skips the task if it is no more in SCHED_AB.
 * 
 * This function currently does nothing
 */
static void update_curr_ab(struct rq *rq)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

/*****************************************************************************/
/* Task parameters updates management                                        */
/*****************************************************************************/

/*
 * This function is invoked when the given task changes priority.
 */
static void prio_changed_ab(struct rq *rq,
			    struct task_struct *p,
			    int oldprio)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

/*
 * Change the allowed CPUs for the given task.
 */
static void set_cpus_allowed_ab(struct task_struct *p,
				const struct cpumask *new_mask)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

/*
 * This function is invoked when the given task parameters are changed and
 * checks if the new parameters are actually different from the previous ones.
 */
bool ab_param_changed(struct task_struct *p, const struct sched_attr *attr)
{
	struct sched_ab_entity *ab_se = &p->ab;

	DEBUG_PRINTK("%s", __FUNCTION__);

	return ab_se->runtime != attr->sched_runtime ||
	       ab_se->deadline != attr->sched_deadline ||
	       ab_se->period != attr->sched_period;
}

/*****************************************************************************/
/* Runqueue management functions                                             */
/*                                                                           */
/* These functions are called when root domains are initialized or removed.  */
/*****************************************************************************/

static void rq_online_ab(struct rq *rq)
{
	DEBUG_PRINTK("%s, %p", __FUNCTION__, (void *)rq);
}

static void rq_offline_ab(struct rq *rq)
{
	DEBUG_PRINTK("%s, %p", __FUNCTION__, (void *)rq);
}

/*****************************************************************************/
/* Definition of ab_sched_class                                              */
/*                                                                           */
/* This structure defines all the function pointer that will be used by the  */
/* other sections of the kernel (expecially sched/core.c) to communicate     */
/* with the scheduling class.                                                */
/*****************************************************************************/

const struct sched_class ab_sched_class = {
	.next			= &fair_sched_class,
	.enqueue_task		= enqueue_task_ab,	// void
	.dequeue_task		= dequeue_task_ab,	// void
	.yield_task		= yield_task_ab,	// void

	.check_preempt_curr	= check_preempt_curr_ab,// void

	.pick_next_task		= pick_next_task_ab,	// struct task_struct *
	.put_prev_task		= put_prev_task_ab,	// void

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_ab,	// int

	.set_cpus_allowed       = set_cpus_allowed_ab,	// void
	.rq_online              = rq_online_ab,		// void
	.rq_offline             = rq_offline_ab,	// void
	.task_woken		= task_woken_ab,	// void
	.switched_from		= switched_from_ab,	// void
#endif

	.set_curr_task          = set_curr_task_ab,	// void
	.task_tick		= task_tick_ab,		// void

	.prio_changed		= prio_changed_ab,	// void
	.switched_to		= switched_to_ab,	// void

	.update_curr		= update_curr_ab,	// void
};

/*****************************************************************************/
/* Initialization functions                                                  */
/*****************************************************************************/

void __init init_sched_ab_class(void)
{
	DEBUG_PRINTK("%s", __FUNCTION__);
}

void init_ab_rq(struct ab_rq *ab_rq)
{
	/* At this point, ab_nr_running is 0 */
	DEBUG_PRINTK("%s", __FUNCTION__);
	
	INIT_LIST_HEAD(&ab_rq->runnable_tasks);
}

/*****************************************************************************/
/* Utility functions to manage the parameters                                */
/*****************************************************************************/

void __ab_clear_params(struct task_struct *p)
{
	struct sched_ab_entity *ab_se = &p->ab;

	ab_se->runtime = 0;
	ab_se->deadline = 0;
	ab_se->period = 0;
	
	ab_se->runnable = 0;
}

void __setparam_ab(struct task_struct *p, const struct sched_attr *attr)
{
	struct sched_ab_entity *ab_se = &p->ab;

	ab_se->runtime = attr->sched_runtime;
	ab_se->deadline = attr->sched_deadline;
	ab_se->period = attr->sched_period;
}

void __getparam_ab(struct task_struct *p, struct sched_attr *attr)
{
	struct sched_ab_entity *ab_se = &p->ab;

	attr->sched_runtime = ab_se->runtime;
	attr->sched_deadline = ab_se->deadline;
	attr->sched_period = ab_se->period;
}

bool __checkparam_ab(const struct sched_attr *attr)
{
	/* The relative deadline cannot be equal to zero. */
	if (attr->sched_deadline == 0)
		return false;

	/* Also the period cannot be equal to zero. */
	if (attr->sched_period == 0)
		return false;

	/* runtime <= deadline <= period */
	if (attr->sched_runtime > attr->sched_deadline ||
	    attr->sched_deadline > attr->sched_period)
		return false;

	return true;
}
