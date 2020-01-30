#ifndef _WORKFLOW_CONFIRM_IMPL_H
#define _WORKFLOW_CONFIRM_IMPL_H

#include <stdbool.h>
#include <stdint.h>

#include <ui/ugui/ugui.h>
#include <workflow/workflow.h>

typedef struct {
    bool result;
    bool done;
    uint32_t timeout_counter;
    uint32_t timeout;
    const char* title;
    const char* body;
    bool scrollable;
    bool longtouch;
    bool accept_only;
    void (*callback)(bool, void*);
    void* callback_param;
    const UG_FONT* font;
} workflow_confirm_data_t;

/**
 * Checks if the user has confirmed the choice,
 * or if the timeout (optional) has expired.
 */
void workflow_confirm_impl_spin(workflow_t* self);

/**
 * Starts this workflow.
 */
void workflow_confirm_impl_init(workflow_t* self);

/**
 * Destroys this workflow.
 */
void workflow_confirm_impl_cleanup(workflow_t* self);

#endif // _WORKFLOW_CONFIRM_IMPL_H
