/*
 * Copyright (C) 2005-2010 Junjiro R. Okajima
 *
 * This program, aufs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * workqueue for asynchronous/super-io operations
 * todo: try new credentials management scheme
 */

#ifndef __AUFS_WKQ_H__
#define __AUFS_WKQ_H__

#ifdef __KERNEL__

#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/aufs_type.h>

struct super_block;

/* ---------------------------------------------------------------------- */

/*
 * in the next operation, wait for the 'nowait' tasks in system-wide workqueue
 */
struct au_nowait_tasks {
	atomic_t		nw_len;
	wait_queue_head_t	nw_wq;
};

/* ---------------------------------------------------------------------- */

typedef void (*au_wkq_func_t)(void *args);

/* wkq flags */
#define AuWkq_WAIT	1
#define AuWkq_PRE	(1 << 1)
#define au_ftest_wkq(flags, name)	((flags) & AuWkq_##name)
#define au_fset_wkq(flags, name) \
	do { (flags) |= AuWkq_##name; } while (0)
#define au_fclr_wkq(flags, name) \
	do { (flags) &= ~AuWkq_##name; } while (0)

/* wkq.c */
int au_wkq_do_wait(unsigned int flags, au_wkq_func_t func, void *args);
int au_wkq_nowait(au_wkq_func_t func, void *args, struct super_block *sb);
void au_nwt_init(struct au_nowait_tasks *nwt);
int __init au_wkq_init(void);
void au_wkq_fin(void);

/* ---------------------------------------------------------------------- */

static inline int au_wkq_wait_pre(au_wkq_func_t func, void *args)
{
	return au_wkq_do_wait(AuWkq_WAIT | AuWkq_PRE, func, args);
}

static inline int au_wkq_wait(au_wkq_func_t func, void *args)
{
	return au_wkq_do_wait(AuWkq_WAIT, func, args);
}

static inline void au_nwt_done(struct au_nowait_tasks *nwt)
{
	if (atomic_dec_and_test(&nwt->nw_len))
		wake_up_all(&nwt->nw_wq);
}

static inline int au_nwt_flush(struct au_nowait_tasks *nwt)
{
	wait_event(nwt->nw_wq, !atomic_read(&nwt->nw_len));
	return 0;
}

#endif /* __KERNEL__ */
#endif /* __AUFS_WKQ_H__ */
