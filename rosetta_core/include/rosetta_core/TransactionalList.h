#pragma once
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

// ── TransactionalList.h ──────────────────────────────────────────────────────
// Generic replication of Rosetta's TransactionalList<T>.
//
// The binary instantiates this for FixupRecord (sizeof=12). The grow
// algorithm uses byte arithmetic and element counts throughout; we replace
// the 12-byte-specific magic-multiply with sizeof(T) division so the logic
// generalises cleanly.
//
// Commit protocol:
//   push_back()  — appends records during translation, never touches _size
//   commit()     — seals the list: _size = element_count()
//   assert_committed() — validates _size before handoff (TransactionalList.h:0x1B)
// ─────────────────────────────────────────────────────────────────────────────

// Maximum element count before abort.
// For sizeof(T)=12: (2^64-1)/12 ≈ 0x1555555555555555, matching the binary.
// Generalised: SIZE_MAX / sizeof(T) rounded down.
template <typename T>
static constexpr uint64_t kTransactionalListMaxCount = static_cast<uint64_t>(-1) / sizeof(T);

template <typename T>
struct TransactionalList {
    T* begin;        // +0x00
    T* end;          // +0x08
    T* end_cap;      // +0x10
    uint64_t _size;  // +0x18  committed count — set by commit(), checked by assert_committed()

    // ── Default-construct to empty ────────────────────────────────────────────
    TransactionalList() : begin(nullptr), end(nullptr), end_cap(nullptr), _size(0) {}

    // Not copyable — owns heap memory
    TransactionalList(const TransactionalList&) = delete;
    TransactionalList& operator=(const TransactionalList&) = delete;

    ~TransactionalList() { ::operator delete(begin); }

    // ── element_count ─────────────────────────────────────────────────────────
    // Number of records currently pushed (live count, before commit).
    uint64_t element_count() const { return static_cast<uint64_t>(end - begin); }

    // ── push_back ─────────────────────────────────────────────────────────────
    // Fast path: write value at end, advance end pointer.
    // Delegates to push_back_slow when the buffer is full.
    void push_back(const T& value) {
        if (end < end_cap) {
            *end = value;
            end = end + 1;
            return;
        }
        push_back_slow(value);
    }

    // ── push_back_slow ────────────────────────────────────────────────────────
    // Grow the buffer then insert. Replicates the slow path at 0xb17c–0xb21c.
    //
    // Growth strategy (confirmed from binary):
    //   current  = end - begin                  (element count before insert)
    //   needed   = current + 1                  abort if > MAX
    //   capacity = end_cap - begin
    //   new_cap  = max(2 * capacity, needed)    then capped at MAX if overflow risk
    //
    // After allocation the new element is placed at new_buf[current] and the
    // existing elements are memcpy'd to new_buf[0..current-1], preserving order.
    // The old buffer is freed with operator delete.
    void push_back_slow(const T& value) {
        uint64_t current = element_count();
        uint64_t needed = current + 1;

        // abort if needed > MAX  (mirrors B.HI loc_B234 → abort())
        if (needed > kTransactionalListMaxCount<T>)
            abort();

        uint64_t capacity = static_cast<uint64_t>(end_cap - begin);

        // new_cap = max(2 * capacity, needed)
        // Guard: if capacity >= MAX/2, doubling would overflow → clamp to MAX.
        // Mirrors: CMP X9, #0xAAA...A / CSEL X0, X10, X8, CC in the binary.
        uint64_t new_cap;
        if (capacity >= kTransactionalListMaxCount<T> / 2) {
            new_cap = kTransactionalListMaxCount<T>;
        } else {
            uint64_t doubled = 2 * capacity;
            new_cap = (doubled > needed) ? doubled : needed;
        }

        // allocate new buffer (new_cap * sizeof(T) bytes)
        // new_cap == 0 is impossible here (needed >= 1), but guard matches binary's CBZ
        T* new_buf = (new_cap > 0) ? static_cast<T*>(::operator new(new_cap * sizeof(T))) : nullptr;

        // write new element at position `current` in the new buffer
        // (mirrors: MADD X9, X22(=current), #0xC, X0(=new_buf))
        T* new_slot = new_buf + current;
        *new_slot = value;
        T* new_end = new_slot + 1;

        // copy existing elements before the new slot
        // (mirrors: LDP src=begin,n=(end-begin); SUB dst=new_slot-n; BL memcpy)
        size_t old_bytes = reinterpret_cast<char*>(end) - reinterpret_cast<char*>(begin);
        T* new_begin = reinterpret_cast<T*>(reinterpret_cast<char*>(new_slot) - old_bytes);
        std::memcpy(new_begin, begin, old_bytes);

        // swap in new buffer, free old
        // end_cap = new_buf + new_cap  (mirrors: MADD X22, X1(=new_cap), #0xC, X0)
        T* old_begin = begin;
        begin = new_begin;
        end = new_end;
        end_cap = new_buf + new_cap;
        ::operator delete(old_begin);
    }

    // ── commit ────────────────────────────────────────────────────────────────
    // Seals the list by writing _size = element_count().
    // Called by commit_pending_fixups() for every fixup list in TranslationResult.
    void commit() { _size = element_count(); }

    // ── assert_committed ──────────────────────────────────────────────────────
    // Validates _size matches the live element count before the list is handed off.
    // Fires the assert from TransactionalList.h:0x1B "calling data on an uncommited fixup list".
    void assert_committed() const {
        assert(_size == element_count() && "calling data on an uncommited fixup list");
    }
};

static_assert(sizeof(TransactionalList<void*>) == 0x20, "TransactionalList size mismatch");
static_assert(offsetof(TransactionalList<void*>, begin) == 0x00,
              "TransactionalList::begin offset mismatch");
static_assert(offsetof(TransactionalList<void*>, end) == 0x08,
              "TransactionalList::end offset mismatch");
static_assert(offsetof(TransactionalList<void*>, end_cap) == 0x10,
              "TransactionalList::end_cap offset mismatch");
static_assert(offsetof(TransactionalList<void*>, _size) == 0x18,
              "TransactionalList::_size offset mismatch");
