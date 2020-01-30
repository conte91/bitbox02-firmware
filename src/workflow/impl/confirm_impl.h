#ifndef _WORKFLOW_CONFIRM_IMPL_H
#define _WORKFLOW_CONFIRM_IMPL_H

#include <stdbool.h>
#include <stdint.h>

#include <ui/ugui/ugui.h>
#include <workflow/workflow.h>

typedef struct {
    bool result;
    bool done;
    confirm_params_t params;
    void (*callback)(bool, void*);
    void* callback_param;
} workflow_confirm_data_t;

/**
 * Checks if the user has confirmed the choice.
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
