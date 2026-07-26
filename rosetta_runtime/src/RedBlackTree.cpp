// System headers MUST come before RuntimeLibC.h so that the #define aliases
// don't interfere with system declarations.
#include <stdlib.h>

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

#include "RedBlackTree.h"

// ASSERT2("RedBlackTree.h", 0xD6, "find_parent_for_insertion_no_duplicates",
//         "expected no duplicates")
[[noreturn]] void rb_assert_no_duplicates() {
    abort();
}
