#include "BestFitAllocator.h"

// The original has four near-identical functions here — insert/fixup written
// once per tree, with the link-set offsets baked in by codegen:
//
//   0x8144  insert_by_size   children at 0x10/0x18, key = FreeBlock::size
//   0x85AC  fixup_size       same links, color at 0x00
//   0x879C  insert_by_addr   children at 0x30/0x38, key = FreeBlock::base_address
//   0x8824  fixup_addr       same links, color at 0x20
//
// fixup_addr is a token-for-token copy of fixup_size with size_*→addr_*, so the
// duplication is an artifact of C++ inlining, not a behavioural difference.  We
// recover it once as a traits-parameterized template and instantiate it twice.
// Hex-Rays renders both as goto-soup only because it inlined the two rotations
// into each of the fixup's four arms; the structure is textbook RB insert-fixup
// and matches RedBlackTree<Node>::fixup_insert in RedBlackTree.h.
//
// The two trees differ in exactly one respect, and it is NOT in the fixup:
// duplicate handling on insert (see SizeLinks/AddrLinks below).

namespace {

// Links keyed on FreeBlock::size (tree at ExecutableHeap+0x38).  Duplicate sizes
// are legal and common — several free spans of equal length coexist — so 0x8144
// has no duplicate check at all and descends left on a tie (`size <= parent`).
struct SizeLinks {
    static uint8_t& color(FreeBlock* n) { return n->size_color; }
    static FreeBlock*& parent(FreeBlock* n) { return n->size_parent; }
    static FreeBlock*& left(FreeBlock* n) { return n->size_left; }
    static FreeBlock*& right(FreeBlock* n) { return n->size_right; }

    // Returns true when `node` belongs in parent's right subtree.
    static bool goes_right(const FreeBlock* node, const FreeBlock* parent) {
        return node->size > parent->size;
    }
    static bool is_duplicate(const FreeBlock*, const FreeBlock*) { return false; }
};

// Links keyed on FreeBlock::base_address (tree at ExecutableHeap+0x48).  Two free
// blocks can never share a base address, and 0x879C treats that case as a no-op:
// it plainly `return`s without linking the node or running the fixup — note this
// is a silent bail, NOT the ASSERT2 that RedBlackTree.h's
// find_parent_for_insertion_no_duplicates raises.
struct AddrLinks {
    static uint8_t& color(FreeBlock* n) { return n->addr_color; }
    static FreeBlock*& parent(FreeBlock* n) { return n->addr_parent; }
    static FreeBlock*& left(FreeBlock* n) { return n->addr_left; }
    static FreeBlock*& right(FreeBlock* n) { return n->addr_right; }

    static bool goes_right(const FreeBlock* node, const FreeBlock* parent) {
        return node->base_address >= parent->base_address;
    }
    static bool is_duplicate(const FreeBlock* node, const FreeBlock* parent) {
        return node->base_address == parent->base_address;
    }
};

// Both fixups reach the tree root through the same {field_00, root} header, so
// the rotations are shared too.  L::left/L::right pick the link set.
template <typename L>
void rotate_left(RedBlackTree<FreeBlock>* tree, FreeBlock* x) {
    FreeBlock* const y = L::right(x);
    L::right(x) = L::left(y);
    if (L::left(y))
        L::parent(L::left(y)) = x;

    FreeBlock* const p = L::parent(x);
    L::parent(y) = p;
    if (!p)
        tree->root = y;
    else if (L::left(p) == x)
        L::left(p) = y;
    else
        L::right(p) = y;

    L::left(y) = x;
    L::parent(x) = y;
}

template <typename L>
void rotate_right(RedBlackTree<FreeBlock>* tree, FreeBlock* x) {
    FreeBlock* const y = L::left(x);
    L::left(x) = L::right(y);
    if (L::right(y))
        L::parent(L::right(y)) = x;

    FreeBlock* const p = L::parent(x);
    L::parent(y) = p;
    if (!p)
        tree->root = y;
    else if (L::left(p) == x)
        L::left(p) = y;
    else
        L::right(p) = y;

    L::right(y) = x;
    L::parent(x) = y;
}

// Standard red-black insert-fixup: recolor while the uncle is red, otherwise
// rotate once or twice and stop.  Transliterated from 0x85AC / 0x8824.
template <typename L>
void fixup(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    L::color(node) = RB_RED;

    for (FreeBlock* parent = L::parent(node); parent && L::color(parent) == RB_RED;
         parent = L::parent(node)) {
        FreeBlock* const grandparent = L::parent(parent);

        if (parent == L::left(grandparent)) {
            FreeBlock* const uncle = L::right(grandparent);
            if (uncle && L::color(uncle) == RB_RED) {
                L::color(uncle) = RB_BLACK;
                L::color(parent) = RB_BLACK;
                L::color(grandparent) = RB_RED;
                node = grandparent;
                continue;
            }
            if (node == L::right(parent)) {
                node = parent;
                rotate_left<L>(tree, node);
            }
            L::color(L::parent(node)) = RB_BLACK;
            L::color(grandparent) = RB_RED;
            rotate_right<L>(tree, grandparent);
        } else {
            FreeBlock* const uncle = L::left(grandparent);
            if (uncle && L::color(uncle) == RB_RED) {
                L::color(uncle) = RB_BLACK;
                L::color(parent) = RB_BLACK;
                L::color(grandparent) = RB_RED;
                node = grandparent;
                continue;
            }
            if (node == L::left(parent)) {
                node = parent;
                rotate_right<L>(tree, node);
            }
            L::color(L::parent(node)) = RB_BLACK;
            L::color(grandparent) = RB_RED;
            rotate_left<L>(tree, grandparent);
        }
        break;  // a rotation always leaves the subtree root black
    }

    L::color(tree->root) = RB_BLACK;
}

// Plain BST descent, then fixup.  `L::is_duplicate` lets the addr tree bail out
// the way 0x879C does; for the size tree it folds away to nothing.
template <typename L>
void insert(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    FreeBlock* cursor = tree->root;
    FreeBlock** slot = &tree->root;

    if (cursor) {
        FreeBlock* parent;
        do {
            parent = cursor;
            if (L::is_duplicate(node, parent))
                return;  // 0x879C returns without linking or fixing up
            cursor = L::goes_right(node, parent) ? L::right(parent) : L::left(parent);
        } while (cursor);

        L::parent(node) = parent;
        L::left(node) = nullptr;
        L::right(node) = nullptr;
        slot = L::goes_right(node, parent) ? &L::right(parent) : &L::left(parent);
    } else {
        L::left(node) = nullptr;
        L::right(node) = nullptr;
        L::parent(node) = nullptr;
    }

    *slot = node;
    fixup<L>(tree, node);
}

}  // namespace

void BestFitAllocator::insert_by_size(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    insert<SizeLinks>(tree, node);
}

void BestFitAllocator::insert_by_addr(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    insert<AddrLinks>(tree, node);
}

void BestFitAllocator::fixup_size(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    fixup<SizeLinks>(tree, node);
}

void BestFitAllocator::fixup_addr(RedBlackTree<FreeBlock>* tree, FreeBlock* node) {
    fixup<AddrLinks>(tree, node);
}

// The removal side (remove_by_size 0x7D5C / remove_by_addr 0x81B8) is not
// recovered.  Both take only the node and reach g_executable_heap.free_by_size /
// .free_by_addr themselves.  When it is written, the delete-fixup can follow the
// same SizeLinks/AddrLinks split used above.
