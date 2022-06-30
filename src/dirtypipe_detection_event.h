#ifndef __DIRTYPIPE_DETECTION_EVENT_H__
#define __DIRTYPIPE_DETECTION_EVENT_H__

#include <stdint.h>

#define TASK_COMM_LEN	16

/****************************************************/
/*!
 *  \brief  Event share between CO-RE code and userland
 */
typedef struct _event_t{
  uint64_t   time;                  // When happened the event
  uint32_t   uid;                   // user id
  uint32_t   pid;                   // process id
  char       process[TASK_COMM_LEN];// comm name (process name)
  char       target[256];           // Path to the file targeted by the exploit
} event_t;

#endif
