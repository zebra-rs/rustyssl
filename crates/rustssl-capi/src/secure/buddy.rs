//! The secure heap's allocator: a binary buddy allocator over offsets into the arena, with no
//! unsafe code. It places blocks exactly as OpenSSL's `crypto/mem_sec.c` does, so programs see
//! the same block sizes and the same successes and failures:
//!
//! - list `n` holds free blocks of `arena_size >> n` bytes; list 0 is the whole arena;
//! - each list is LIFO, and an allocation takes the head of the smallest list that fits;
//! - an empty list splits the head of the nearest larger one, and the upper half becomes the
//!   new head, so splitting continues from the top of the arena down;
//! - a freed block merges with its buddy while the buddy is free too.
//!
//! OpenSSL threads its free lists through the free blocks themselves. These are kept beside the
//! arena instead, so nothing but the application's data is ever written into it, and an index
//! is stored per minimum-size slot.

/// Marks the end of a free list.
const NONE: u32 = u32::MAX;

/// A misuse OpenSSL catches with `OPENSSL_assert`, which aborts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Misuse {
    /// The pointer isn't the start of a block (`sh_getlist`'s and `sh_testbit`'s assertions).
    NotABlock,
    /// The block is already free (`sh_clearbit`'s assertion on `bitmalloc`).
    DoubleFree,
}

pub(crate) struct Buddy {
    arena_size: usize,
    minsize: usize,
    /// How many lists there are (OpenSSL's `freelist_size`).
    lists: usize,
    /// For each node of the implicit binary tree (node `(1 << list) + offset / block_size`):
    /// whether that block exists, free or allocated (OpenSSL's `bittable`) ...
    exists: Vec<bool>,
    /// ... and whether it's allocated (`bitmalloc`).
    allocated: Vec<bool>,
    /// Each list's head, as a slot (`offset / minsize`).
    heads: Vec<u32>,
    /// The doubly linked free lists, per slot.
    next: Vec<u32>,
    previous: Vec<u32>,
}

impl Buddy {
    /// An allocator for an arena of `arena_size` bytes in blocks of at least `minsize` bytes,
    /// both powers of two, or `None` if that gives fewer than four blocks (OpenSSL's "prevent
    /// allocations of size 0") or more than this allocator indexes.
    pub(crate) fn new(arena_size: usize, minsize: usize) -> Option<Self> {
        if !arena_size.is_power_of_two() || !minsize.is_power_of_two() {
            return None;
        }
        let slots = arena_size / minsize;
        let nodes = slots.checked_mul(2)?;
        // OpenSSL's bit tables need at least one byte.
        if nodes >> 3 == 0 || u32::try_from(slots).ok()? == NONE {
            return None;
        }
        let lists = usize::try_from(nodes.ilog2()).ok()?;
        let mut buddy = Self {
            arena_size,
            minsize,
            lists,
            exists: vec![false; nodes],
            allocated: vec![false; nodes],
            heads: vec![NONE; lists],
            next: vec![NONE; slots],
            previous: vec![NONE; slots],
        };
        buddy.set(Table::Exists, 0, 0, true);
        buddy.push(0, 0);
        Some(buddy)
    }

    /// The size of the blocks on `list`.
    fn block_size(&self, list: usize) -> usize {
        self.arena_size >> list
    }

    /// The tree node of the block at `offset` on `list`.
    fn node(&self, offset: usize, list: usize) -> usize {
        (1 << list) + offset / self.block_size(list)
    }

    fn slot(&self, offset: usize) -> usize {
        offset / self.minsize
    }

    fn get(&self, table: Table, offset: usize, list: usize) -> bool {
        let node = self.node(offset, list);
        let table = match table {
            Table::Exists => &self.exists,
            Table::Allocated => &self.allocated,
        };
        table.get(node).copied().unwrap_or(false)
    }

    fn set(&mut self, table: Table, offset: usize, list: usize, value: bool) {
        let node = self.node(offset, list);
        let table = match table {
            Table::Exists => &mut self.exists,
            Table::Allocated => &mut self.allocated,
        };
        if let Some(bit) = table.get_mut(node) {
            *bit = value;
        }
    }

    /// Adds the block at `offset` to the head of `list`.
    fn push(&mut self, list: usize, offset: usize) {
        let slot = self.slot(offset);
        let head = self.heads.get(list).copied().unwrap_or(NONE);
        let index = u32::try_from(slot).unwrap_or(NONE);
        if let Some(next) = self.next.get_mut(slot) {
            *next = head;
        }
        if let Some(previous) = self.previous.get_mut(slot) {
            *previous = NONE;
        }
        if let Some(previous) = usize::try_from(head)
            .ok()
            .filter(|_| head != NONE)
            .and_then(|h| self.previous.get_mut(h))
        {
            *previous = index;
        }
        if let Some(entry) = self.heads.get_mut(list) {
            *entry = index;
        }
    }

    /// Removes the block at `offset` from `list`, wherever it is in the list.
    fn remove(&mut self, list: usize, offset: usize) {
        let slot = self.slot(offset);
        let next = self.next.get(slot).copied().unwrap_or(NONE);
        let previous = self.previous.get(slot).copied().unwrap_or(NONE);
        if previous == NONE {
            if let Some(head) = self.heads.get_mut(list) {
                *head = next;
            }
        } else if let Some(entry) = usize::try_from(previous)
            .ok()
            .and_then(|p| self.next.get_mut(p))
        {
            *entry = next;
        }
        if next != NONE
            && let Some(entry) = usize::try_from(next)
                .ok()
                .and_then(|n| self.previous.get_mut(n))
        {
            *entry = previous;
        }
    }

    /// The offset of the head of `list`.
    fn head(&self, list: usize) -> Option<usize> {
        let head = *self.heads.get(list)?;
        if head == NONE {
            return None;
        }
        Some(usize::try_from(head).ok()? * self.minsize)
    }

    /// Allocates a block of at least `size` bytes, returning its offset (`sh_malloc`). Zero
    /// bytes get a minimum-size block.
    pub(crate) fn allocate(&mut self, size: usize) -> Option<usize> {
        if size > self.arena_size {
            return None;
        }
        let mut list = self.lists.checked_sub(1)?;
        let mut block = self.minsize;
        while block < size {
            block <<= 1;
            list = list.checked_sub(1)?;
        }
        // The nearest list at or above `list` (in size) with a free block.
        let mut source = (0..=list).rev().find(|l| self.head(*l).is_some())?;
        while source != list {
            let block = self.head(source)?;
            self.set(Table::Exists, block, source, false);
            self.remove(source, block);
            source += 1;
            self.set(Table::Exists, block, source, true);
            self.push(source, block);
            let upper = block + self.block_size(source);
            self.set(Table::Exists, upper, source, true);
            self.push(source, upper);
        }
        let chunk = self.head(list)?;
        self.set(Table::Allocated, chunk, list, true);
        self.remove(list, chunk);
        Some(chunk)
    }

    /// The list of the block starting at `offset` (`sh_getlist`, with `sh_testbit`'s checks).
    fn list_of(&self, offset: usize) -> Result<usize, Misuse> {
        if offset >= self.arena_size {
            return Err(Misuse::NotABlock);
        }
        // Start from the smallest block that could start there and walk up the tree.
        let mut node = (self.arena_size + offset) / self.minsize;
        let mut list = self.lists.checked_sub(1).ok_or(Misuse::NotABlock)?;
        while node != 0 {
            if self.exists.get(node).copied().unwrap_or(false) {
                break;
            }
            if node & 1 != 0 {
                return Err(Misuse::NotABlock);
            }
            node >>= 1;
            list = list.checked_sub(1).ok_or(Misuse::NotABlock)?;
        }
        let aligned = offset & (self.block_size(list) - 1) == 0;
        if node == 0 || !aligned || !self.get(Table::Exists, offset, list) {
            return Err(Misuse::NotABlock);
        }
        Ok(list)
    }

    /// The size of the block starting at `offset` (`sh_actual_size`).
    pub(crate) fn size_of(&self, offset: usize) -> Result<usize, Misuse> {
        Ok(self.block_size(self.list_of(offset)?))
    }

    /// The size of the allocated block starting at `offset`.
    pub(crate) fn allocated_size(&self, offset: usize) -> Result<usize, Misuse> {
        let list = self.list_of(offset)?;
        if !self.get(Table::Allocated, offset, list) {
            return Err(Misuse::DoubleFree);
        }
        Ok(self.block_size(list))
    }

    /// The free buddy of the block at `offset` on `list`, if there is one.
    fn free_buddy(&self, offset: usize, list: usize) -> Option<usize> {
        let node = self.node(offset, list) ^ 1;
        let exists = self.exists.get(node).copied().unwrap_or(false);
        let allocated = self.allocated.get(node).copied().unwrap_or(false);
        (exists && !allocated).then(|| (node & ((1 << list) - 1)) * self.block_size(list))
    }

    /// Frees the block at `offset` (`sh_free`), merging it with free buddies.
    pub(crate) fn free(&mut self, offset: usize) -> Result<(), Misuse> {
        let mut list = self.list_of(offset)?;
        if !self.get(Table::Allocated, offset, list) {
            return Err(Misuse::DoubleFree);
        }
        self.set(Table::Allocated, offset, list, false);
        self.push(list, offset);
        let mut block = offset;
        while let Some(buddy) = self.free_buddy(block, list) {
            self.set(Table::Exists, block, list, false);
            self.remove(list, block);
            self.set(Table::Exists, buddy, list, false);
            self.remove(list, buddy);
            list -= 1;
            block = block.min(buddy);
            self.set(Table::Exists, block, list, true);
            self.push(list, block);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Table {
    Exists,
    Allocated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_blocks_like_openssl() {
        // The reference OpenSSL 3.5 gives these offsets in a 4096-byte arena with 16-byte
        // minimum blocks: 0 and 17 bytes, then 100 (abi probe on macOS and Linux).
        let mut buddy = Buddy::new(4096, 16).unwrap();
        let a = buddy.allocate(0).unwrap();
        let b = buddy.allocate(17).unwrap();
        let c = buddy.allocate(100).unwrap();
        assert_eq!((a, b, c), (4080, 4032, 3840));
        assert_eq!(buddy.size_of(a), Ok(16));
        assert_eq!(buddy.size_of(b), Ok(32));
        assert_eq!(buddy.size_of(c), Ok(128));
        assert_eq!(buddy.allocate(4096), None);
        for offset in [a, b, c] {
            buddy.free(offset).unwrap();
        }
        assert_eq!(buddy.allocate(4096), Some(0));
    }

    #[test]
    fn too_small_arenas_fail() {
        assert!(Buddy::new(32, 16).is_none());
        assert!(Buddy::new(64, 16).is_some());
        assert!(Buddy::new(48, 16).is_none());
    }

    #[test]
    fn misuse_is_reported() {
        let mut buddy = Buddy::new(4096, 16).unwrap();
        let block = buddy.allocate(64).unwrap();
        assert_eq!(buddy.size_of(block + 16), Err(Misuse::NotABlock));
        assert_eq!(buddy.size_of(4096), Err(Misuse::NotABlock));
        assert_eq!(buddy.free(block + 32), Err(Misuse::NotABlock));
        buddy.free(block).unwrap();
        // Freed and merged back into the whole arena.
        assert_eq!(buddy.free(block), Err(Misuse::NotABlock));
        let small = buddy.allocate(16).unwrap();
        let _keep = buddy.allocate(16).unwrap();
        buddy.free(small).unwrap();
        assert_eq!(buddy.free(small), Err(Misuse::DoubleFree));
    }

    #[test]
    fn random_use_keeps_blocks_disjoint_and_merges_back() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let arena = 1 << 14;
        let mut buddy = Buddy::new(arena, 16).unwrap();
        let mut live: Vec<(usize, usize)> = Vec::new();
        // Miri is slow; a shorter run still covers splitting and merging at every level.
        let rounds = if cfg!(miri) { 2_000 } else { 20_000 };
        for _ in 0..rounds {
            if live.is_empty() || random() % 3 != 0 {
                let size = usize::try_from(random() % 700).unwrap();
                if let Some(offset) = buddy.allocate(size) {
                    let actual = buddy.size_of(offset).unwrap();
                    assert!(actual >= size.max(16) && actual.is_power_of_two());
                    assert_eq!(offset % actual, 0);
                    assert!(offset + actual <= arena);
                    for (other, other_size) in &live {
                        assert!(offset + actual <= *other || other + other_size <= offset);
                    }
                    live.push((offset, actual));
                }
            } else {
                let index = usize::try_from(random()).unwrap() % live.len();
                let (offset, _) = live.swap_remove(index);
                buddy.free(offset).unwrap();
            }
        }
        for (offset, _) in live {
            buddy.free(offset).unwrap();
        }
        assert_eq!(buddy.allocate(arena), Some(0));
    }
}
