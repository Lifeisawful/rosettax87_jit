#include "CodeFragmentMetadata.h"

// The original CodeFragmentMetadata.cpp holds three functions, named by their
// own ASSERT("CodeFragmentMetadata.cpp", …) calls:
//
//   0x7478  instruction_extents_for_arm_address  — maps an arm pc back to the
//           x86/arm instruction extents around it; errors with "code fragment
//           does not contain the given arm address".  Needs the offset-map types
//           (DeltaCodedOffsetMap / OffsetPairArray), not recovered yet.
//   ~0x7828 resolve_branch_target                — not recovered yet.
//   0x78F4  CodeFragmentFreeList::push_back      — appends a retired fragment to
//           a free list.  Only reached from the fragment-retirement paths
//           (sub_BF4C, remove_fragment, remove_arm_tree_only_translation), none
//           of which allocate_chunk touches, so it is not recovered yet either.
//
// push_back living here is also why CodeFragmentFreeList's members are
// `_head`/`_tail`: the list class is declared alongside the fragment type in the
// original.
