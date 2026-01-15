//! Fixed-size, stack-allocated stack for zero-allocation evaluation.
//!
//! This module provides a `FixedStack` that uses `MaybeUninit` to avoid
//! default initialization costs. All operations are panic-free and return
//! `Result` types.

use core::mem::MaybeUninit;

use crate::error::PolicyError;

/// A fixed-size stack allocated on the stack frame.
///
/// Uses `MaybeUninit` to avoid initialization overhead.
/// All operations are panic-free and return explicit errors.
pub struct FixedStack<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    len: usize,
}

impl<T, const N: usize> FixedStack<T, N> {
    /// Create a new empty fixed stack.
    #[inline]
    pub fn new() -> Self {
        FixedStack {
            // SAFETY: MaybeUninit does not require initialization
            buf: unsafe { MaybeUninit::uninit().assume_init() },
            len: 0,
        }
    }

    /// Push an item onto the stack.
    ///
    /// Returns `Err(PolicyError::EvalStackOverflow)` if the stack is full.
    #[inline]
    pub fn push(&mut self, value: T) -> Result<(), PolicyError> {
        if self.len >= N {
            return Err(PolicyError::EvalStackOverflow { max: N });
        }
        // SAFETY: len < N, so this slot is valid
        self.buf[self.len].write(value);
        self.len += 1;
        Ok(())
    }

    /// Pop an item from the stack.
    ///
    /// Returns `None` if the stack is empty.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: this slot was initialized by a previous push
        Some(unsafe { self.buf[self.len].assume_init_read() })
    }

    /// Returns the current number of items in the stack.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the stack is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T, const N: usize> Drop for FixedStack<T, N> {
    fn drop(&mut self) {
        // Drop only the initialized elements
        for i in 0..self.len {
            // SAFETY: elements 0..len are initialized
            unsafe {
                self.buf[i].assume_init_drop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop() {
        let mut stack: FixedStack<i32, 4> = FixedStack::new();
        assert!(stack.is_empty());

        stack.push(1).unwrap();
        stack.push(2).unwrap();
        stack.push(3).unwrap();

        assert_eq!(stack.len(), 3);
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());
    }

    #[test]
    fn test_overflow() {
        let mut stack: FixedStack<i32, 2> = FixedStack::new();
        assert!(stack.push(1).is_ok());
        assert!(stack.push(2).is_ok());
        let err = stack.push(3).unwrap_err();
        assert!(matches!(err, PolicyError::EvalStackOverflow { max: 2 }));
    }

    #[test]
    fn test_drop_partial() {
        use std::cell::Cell;
        use std::rc::Rc;

        let counter = Rc::new(Cell::new(0));
        struct DropCounter(Rc<Cell<i32>>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        {
            let mut stack: FixedStack<DropCounter, 4> = FixedStack::new();
            stack.push(DropCounter(Rc::clone(&counter))).unwrap();
            stack.push(DropCounter(Rc::clone(&counter))).unwrap();
            // Only 2 items pushed, capacity is 4
        }
        // Both items should have been dropped
        assert_eq!(counter.get(), 2);
    }
}
