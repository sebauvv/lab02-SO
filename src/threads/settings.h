#ifndef SETTINGS_H
#define SETTINGS_H

/** This file is intended to control implemented functionalities.
   It makes easy for you to turn on(off) functionalities implemented
   in src/threads. */


/**< Use nested donation of priority(I don't like it). */
#define THREAD_DONATE_NEST

/**< Do not want user programs to do nested donation. */
#ifdef USERPROG
#ifdef THREAD_DONATE_NEST
#undef THREAD_DONATE_NEST
#endif /**< THREAD_DONATE_NEST */
#endif /**< USERPROG */

#endif /*<< threads/settings.h */
