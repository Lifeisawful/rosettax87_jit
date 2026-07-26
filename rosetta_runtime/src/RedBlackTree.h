#pragma once

#include <cstddef>
#include <cstdint>

// Header-only red-black tree, keyed via rb_key(Node*), with no duplicate keys.
//
// The original really is a header — ASSERT2 in
// find_parent_for_insertion_no_duplicates reports "RedBlackTree.h":214, and
// the runtime emits one instantiation per node type.  Node must provide:
//
//   uint8_t bst_color;      RB_RED / RB_BLACK
//   Node   *bst_parent;
//   Node   *bst_left;
//   Node   *bst_right;
//
// plus a `uint64_t rb_key(const Node*)` overload findable by ADL.  The key is a
// hook rather than a fixed member because the same node type is filed in
// different trees under different keys (CodeFragmentMetadata sorts by arm_base
// in the arm tree and by x86_base in the x86 trees).
//
// Evidence (CodeFragmentMetadata / arm_tree instantiation):
//   0xAA74  RedBlackTree::insert
//   0xAAD0  RedBlackTree::find_parent_for_insertion_no_duplicates
//   0xAB44  RedBlackTree::fixup_insert
//
// The FreeBlock trees (ExecutableHeap::free_by_size / free_by_addr) are *not*
// this: each FreeBlock carries two independent link sets, so they get their
// own BestFitAllocator::insert_by_size / insert_by_addr.

enum RedBlackColor : uint8_t {
    RB_BLACK = 0,
    RB_RED = 1,
};

[[noreturn]] void rb_assert_no_duplicates();

#pragma pack(push, 2)
template <typename Node>
struct RedBlackTree {
    uint64_t field_00;
    Node* root;

    void insert(Node* node);

    // Returns the node that `new_node` becomes a child of, or nullptr when the
    // tree is empty.  Traps if the key is already present.
    Node* find_parent_for_insertion_no_duplicates(Node* new_node);

    void fixup_insert(Node* node);

   private:
    void rotate_left(Node* x);
    void rotate_right(Node* x);
};
#pragma pack(pop)

// Layout is node-type independent (the tree holds one pointer), so a deliberately
// incomplete probe type is enough to pin it — and it keeps these asserts honest
// even if no real instantiation exists in a given TU.
//
// 00000000 #pragma pack(push, 2)
// 00000000 struct RedBlackTree // sizeof=0x10
// 00000000 {                                       // XREF: ExecutableHeap.free_by_size/r
// 00000000                                         // ExecutableHeap.free_by_addr/r ...
// 00000000     unsigned __int64 sentinel;
// 00000008     void *root;                         // XREF: vtable_single_step_with_resume+54/o
// 00000008                                         // vtable_single_step_with_resume+68/r ...
// 00000010 };
// 00000010 #pragma pack(pop)
struct RbLayoutProbe;

static_assert(sizeof(RedBlackTree<RbLayoutProbe>) == 0x10);
static_assert(offsetof(RedBlackTree<RbLayoutProbe>, field_00) == 0x00);
static_assert(offsetof(RedBlackTree<RbLayoutProbe>, root) == 0x08);

template <typename Node>
void RedBlackTree<Node>::insert(Node* node) {
    Node* parent = find_parent_for_insertion_no_duplicates(node);
    node->bst_parent = parent;
    node->bst_left = nullptr;
    node->bst_right = nullptr;

    Node** slot;
    if (parent)
        slot = (rb_key(node) < rb_key(parent)) ? &parent->bst_left : &parent->bst_right;
    else
        slot = &root;
    *slot = node;

    fixup_insert(node);
}

template <typename Node>
Node* RedBlackTree<Node>::find_parent_for_insertion_no_duplicates(Node* new_node) {
    Node* cursor = root;
    if (!cursor)
        return nullptr;

    const uint64_t key = rb_key(new_node);
    Node* parent;
    do {
        const uint64_t cursor_key = rb_key(cursor);
        if (key >= cursor_key) {
            if (cursor_key >= key)
                rb_assert_no_duplicates();  // ASSERT2("RedBlackTree.h", 214, …)
            parent = cursor;
            cursor = cursor->bst_right;
        } else {
            parent = cursor;
            cursor = cursor->bst_left;
        }
    } while (cursor);
    return parent;
}

template <typename Node>
void RedBlackTree<Node>::rotate_left(Node* x) {
    Node* const y = x->bst_right;
    x->bst_right = y->bst_left;
    if (y->bst_left)
        y->bst_left->bst_parent = x;
    Node* const parent = x->bst_parent;
    y->bst_parent = parent;
    if (!parent)
        root = y;
    else if (parent->bst_left == x)
        parent->bst_left = y;
    else
        parent->bst_right = y;
    y->bst_left = x;
    x->bst_parent = y;
}

template <typename Node>
void RedBlackTree<Node>::rotate_right(Node* x) {
    Node* const y = x->bst_left;
    x->bst_left = y->bst_right;
    if (y->bst_right)
        y->bst_right->bst_parent = x;
    Node* const parent = x->bst_parent;
    y->bst_parent = parent;
    if (!parent)
        root = y;
    else if (parent->bst_left == x)
        parent->bst_left = y;
    else
        parent->bst_right = y;
    y->bst_right = x;
    x->bst_parent = y;
}

template <typename Node>
void RedBlackTree<Node>::fixup_insert(Node* node) {
    node->bst_color = RB_RED;

    for (Node* parent = node->bst_parent; parent && parent->bst_color == RB_RED;
         parent = node->bst_parent) {
        Node* const grandparent = parent->bst_parent;

        if (parent == grandparent->bst_left) {
            Node* const uncle = grandparent->bst_right;
            if (uncle && uncle->bst_color == RB_RED) {
                uncle->bst_color = RB_BLACK;
                parent->bst_color = RB_BLACK;
                grandparent->bst_color = RB_RED;
                node = grandparent;
                continue;
            }
            if (node == parent->bst_right) {
                node = parent;
                rotate_left(node);
            }
            node->bst_parent->bst_color = RB_BLACK;
            grandparent->bst_color = RB_RED;
            rotate_right(grandparent);
        } else {
            Node* const uncle = grandparent->bst_left;
            if (uncle && uncle->bst_color == RB_RED) {
                uncle->bst_color = RB_BLACK;
                parent->bst_color = RB_BLACK;
                grandparent->bst_color = RB_RED;
                node = grandparent;
                continue;
            }
            if (node == parent->bst_left) {
                node = parent;
                rotate_right(node);
            }
            node->bst_parent->bst_color = RB_BLACK;
            grandparent->bst_color = RB_RED;
            rotate_left(grandparent);
        }
        break;  // a rotation always leaves the subtree root black
    }

    root->bst_color = RB_BLACK;
}
