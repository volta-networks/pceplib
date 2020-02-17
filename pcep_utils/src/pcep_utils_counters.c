/*
 * Implementation of PCEP Counters.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pcep_utils_counters.h"
#include "pcep_utils_logging.h"

struct counters_group *create_counters_group(const char *group_name, uint16_t max_subgroups)
{
    if (group_name == NULL)
    {
        pcep_log(LOG_INFO, "Cannot create counters group: group_name is NULL.");
        return NULL;
    }

    if (max_subgroups > MAX_COUNTER_GROUPS)
    {
        pcep_log(LOG_INFO, "Cannot create counters group: max_subgroups [%d] is larger than max the [%d].",
                max_subgroups, MAX_COUNTER_GROUPS);
        return NULL;
    }

    struct counters_group *group = malloc(sizeof(struct counters_group));
    memset(group, 0, sizeof(struct counters_group));
    group->subgroups = malloc(sizeof(struct counters_subgroup*) * (max_subgroups + 1));
    memset(group->subgroups, 0, sizeof(struct counters_subgroup*) * (max_subgroups + 1));

    strcpy(group->counters_group_name, group_name);
    group->max_subgroups = max_subgroups;
    group->start_time = time(NULL);

    return group;
}

struct counters_subgroup *create_counters_subgroup(const char *subgroup_name, uint16_t subgroup_id, uint16_t max_counters)
{
    if (subgroup_name == NULL)
    {
        pcep_log(LOG_INFO, "Cannot create counters subgroup: subgroup_name is NULL.");
        return NULL;
    }

    if (max_counters > MAX_COUNTERS)
    {
        pcep_log(LOG_INFO, "Cannot create counters subgroup: max_counters [%d] is larger than max the [%d].",
                max_counters, MAX_COUNTERS);
        return NULL;
    }

    if (subgroup_id > MAX_COUNTER_GROUPS)
    {
        pcep_log(LOG_INFO, "Cannot create counters subgroup: subgroup_id [%d] is larger than max the [%d].",
                subgroup_id, MAX_COUNTER_GROUPS);
        return NULL;
    }

    struct counters_subgroup *subgroup = malloc(sizeof(struct counters_subgroup));
    memset(subgroup, 0, sizeof(struct counters_subgroup));
    subgroup->counters = malloc(sizeof(struct counter*) * (max_counters + 1));
    memset(subgroup->counters, 0, sizeof(struct counter*) * (max_counters + 1));

    strcpy(subgroup->counters_subgroup_name, subgroup_name);
    subgroup->subgroup_id = subgroup_id;
    subgroup->max_counters = max_counters;

    return subgroup;
}

struct counters_subgroup *clone_counters_subgroup(struct counters_subgroup *subgroup, const char *subgroup_name, uint16_t subgroup_id)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot clone counters subgroup: input counters_subgroup is NULL.");
        return NULL;
    }

    if (subgroup_name == NULL)
    {
        pcep_log(LOG_INFO, "Cannot clone counters subgroup: subgroup_name is NULL.");
        return NULL;
    }

    if (subgroup_id > MAX_COUNTER_GROUPS)
    {
        pcep_log(LOG_INFO, "Cannot clone counters subgroup: subgroup_id [%d] is larger than max the [%d].",
                subgroup_id, MAX_COUNTER_GROUPS);
        return NULL;
    }

    struct counters_subgroup *cloned_subgroup = create_counters_subgroup(subgroup_name, subgroup_id, subgroup->max_counters);
    int i = 0;
    for (; i <= subgroup->max_counters; i++)
    {
        struct counter *counter = subgroup->counters[i];
        if (counter != NULL)
        {
            create_subgroup_counter(cloned_subgroup, counter->counter_id, counter->counter_name);
        }
    }

    return cloned_subgroup;
}

bool add_counters_subgroup(struct counters_group *group, struct counters_subgroup *subgroup)
{
    if (group == NULL)
    {
        pcep_log(LOG_INFO, "Cannot add counters subgroup: counters_group is NULL.");
        return false;
    }

    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot add counters subgroup: counters_subgroup is NULL.");
        return false;
    }

    if (subgroup->subgroup_id > group->max_subgroups)
    {
        pcep_log(LOG_INFO, "Cannot add counters subgroup: counters_subgroup id [%d] is larger than the group max_subgroups [%d].",
                subgroup->subgroup_id, group->max_subgroups);
        return false;
    }

    group->num_subgroups++;
    group->subgroups[subgroup->subgroup_id] = subgroup;

    return true;
}

bool create_subgroup_counter(struct counters_subgroup *subgroup, uint32_t counter_id, const char *counter_name)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot create subgroup counter: counters_subgroup is NULL.");
        return false;
    }

    if (counter_id > subgroup->max_counters)
    {
        pcep_log(LOG_INFO, "Cannot create subgroup counter: counter_id [%d] is larger than the subgroup max_counters [%d].",
                counter_id, subgroup->max_counters);
        return false;
    }

    if (counter_name == NULL)
    {
        pcep_log(LOG_INFO, "Cannot create subgroup counter: counter_name is NULL.");
        return NULL;
    }

    struct counter *counter = malloc(sizeof(struct counter));
    memset(counter, 0, sizeof(struct counter));
    counter->counter_id = counter_id;
    strcpy(counter->counter_name, counter_name);

    subgroup->num_counters++;
    subgroup->counters[counter->counter_id] = counter;

    return true;
}

bool delete_counters_group(struct counters_group *group)
{
    if (group == NULL)
    {
        pcep_log(LOG_INFO, "Cannot delete group counters: counters_group is NULL.");
        return false;
    }

    int i = 0;
    for (; i <= group->max_subgroups; i++)
    {
        struct counters_subgroup *subgroup = group->subgroups[i];
        if (subgroup != NULL)
        {
            delete_counters_subgroup(subgroup);
        }
    }

    free(group->subgroups);
    free(group);

    return true;
}

bool delete_counters_subgroup(struct counters_subgroup *subgroup)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot delete subgroup counters: counters_subgroup is NULL.");
        return false;
    }

    int i = 0;
    for (; i <= subgroup->max_counters; i++)
    {
        struct counter *counter = subgroup->counters[i];
        if (counter != NULL)
        {
            free(counter);
        }
    }

    free(subgroup->counters);
    free(subgroup);

    return true;
}

bool reset_group_counters(struct counters_group *group)
{
    if (group == NULL)
    {
        pcep_log(LOG_INFO, "Cannot reset group counters: counters_group is NULL.");
        return false;
    }

    int i = 0;
    for (; i <= group->max_subgroups; i++)
    {
        struct counters_subgroup *subgroup = group->subgroups[i];
        if (subgroup != NULL)
        {
            reset_subgroup_counters(subgroup);
        }
    }

    group->start_time = time(NULL);

    return true;
}

bool reset_subgroup_counters(struct counters_subgroup *subgroup)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot reset subgroup counters: counters_subgroup is NULL.");
        return false;
    }

    int i = 0;
    for (; i <= subgroup->max_counters; i++)
    {
        struct counter *counter = subgroup->counters[i];
        if (counter != NULL)
        {
            counter->counter_value = 0;
        }
    }

    return true;
}

bool increment_counter(struct counters_group *group, uint16_t subgroup_id, uint16_t counter_id)
{
    if (group == NULL)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: counters_group is NULL.");
        return false;
    }

    if (subgroup_id >= group->max_subgroups)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: subgroup_id [%d] is larger than the group max_subgroups [%d].",
                subgroup_id, group->max_subgroups);
        return false;
    }

    struct counters_subgroup *subgroup = group->subgroups[subgroup_id];
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: counters_subgroup in counters_group is NULL.");
        return false;
    }

    return increment_subgroup_counter(subgroup, counter_id);
}

bool increment_subgroup_counter(struct counters_subgroup *subgroup, uint16_t counter_id)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: counters_subgroup is NULL.");
        return false;
    }

    if (counter_id >= subgroup->max_counters)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: counter_id [%d] is larger than the subgroup max_counters [%d].",
                counter_id, subgroup->max_counters);
        return false;
    }

    if (subgroup->counters[counter_id] == NULL)
    {
        pcep_log(LOG_INFO, "Cannot increment counter: No counter exists for counter_id [%d].", counter_id);
        return false;
    }

    subgroup->counters[counter_id]->counter_value++;

    return true;
}

bool dump_counters_group_to_log(struct counters_group *group)
{
    if (group == NULL)
    {
        pcep_log(LOG_INFO, "Cannot dump group counters to log: counters_group is NULL.");
        return false;
    }

    time_t now = time(NULL);
    pcep_log(LOG_INFO, "PCEP Counters group:\n  %s \n  Sub-Groups [%d] \n  Active for [%d seconds]",
            group->counters_group_name, group->num_subgroups, (now - group->start_time));

    int i = 0;
    for (; i <= group->max_subgroups; i++)
    {
        struct counters_subgroup *subgroup = group->subgroups[i];
        if (subgroup != NULL)
        {
            dump_counters_subgroup_to_log(subgroup);
        }
    }

    return true;
}

bool dump_counters_subgroup_to_log(struct counters_subgroup *subgroup)
{
    if (subgroup == NULL)
    {
        pcep_log(LOG_INFO, "Cannot dump subgroup counters to log: counters_subgroup is NULL.");
        return false;
    }

    pcep_log(LOG_INFO, "\tPCEP Counters sub-group [%s] with [%d] counters",
            subgroup->counters_subgroup_name, subgroup->num_counters);

    int i = 0;
    for (; i <= subgroup->max_counters; i++)
    {
        struct counter *counter = subgroup->counters[i];
        if (counter != NULL)
        {
            pcep_log(LOG_INFO, "\t\t%s %d",
                    counter->counter_name, counter->counter_value);
        }
    }

    return true;
}
