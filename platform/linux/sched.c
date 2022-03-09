#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int
sched_ctx_init(struct sched_ctx *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

int
sched_ctx_destroy(struct sched_ctx *ctx)
{
    return pthread_cond_destroy(&ctx->cond);
}

int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;
    // interruptedのフラグが立っていたら errno に EINTR を設定してエラーを返す
    if (ctx->interrupted) {
        errno = EINTR;
        return -1;
    }
    ctx->wc++;
    // pthread_cond_broadcast() が呼ばれるまでスレッドを休止させる
    // abstime が指定されていたら指定時刻に起床する pthread_cond_timedwait() を使用する
    // ※ 休止する際には mutex がアンロックされ、起床する際にロックされた状態で戻ってくる
    if (abstime) {
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    } else {
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--;
    //休止中だったスレッド全てが起床したら interrupted フラグを下げる
    if (ctx->interrupted) {
        if (!ctx->wc) {
            ctx->interrupted = 0;
        }
        //errno に EINTR を設定してエラーを返す
        errno = EINTR;
        return -1;
    }
    return ret;
}

int
sched_wakeup(struct sched_ctx *ctx)
{
    return pthread_cond_broadcast(&ctx->cond);
}

int
sched_interrupt(struct sched_ctx *ctx)
{
    ctx->interrupted = 1;
    //休止しているスレッドを起床させる
    return pthread_cond_broadcast(&ctx->cond);
}
