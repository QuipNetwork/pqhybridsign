// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sign_stateful` must not be callable through a shared reference: it
//! advances the one-time leaf state, so it requires `&mut`.

use pqhybridsign::stateful::{KeyIdentity, LeafJournal, StatefulHybridSignatureScheme};
use pqhybridsign::shrincs::{keygen, H5};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default, Clone)]
struct MemoryJournal {
    committed: Rc<RefCell<Vec<u32>>>,
    bound: Rc<RefCell<Option<KeyIdentity>>>,
}

impl LeafJournal for MemoryJournal {
    type Error = core::convert::Infallible;

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        self.committed.borrow_mut().push(leaf);
        Ok(())
    }

    fn next_leaf(&self) -> u32 {
        self.committed
            .borrow()
            .iter()
            .copied()
            .max()
            .map_or(0, |m| m + 1)
    }

    fn bound_key(&self) -> Option<KeyIdentity> {
        *self.bound.borrow()
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        *self.bound.borrow_mut() = Some(key);
        Ok(())
    }
}

fn main() {
    let (sk, _pk) = keygen::<H5>(&[1u8; 32], 4).expect("keygen");
    let mut journal = MemoryJournal::default();

    let _sig = H5::sign_stateful(&sk, &mut journal, b"hello", b"ctx");
}
