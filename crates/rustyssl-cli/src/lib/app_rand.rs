//! `apps/lib/app_rand.c`: `-rand` and `-writerand`, and the configuration's `RANDFILE`.

use std::cell::RefCell;

use rustyssl_ossl::rand;

use super::io;
use super::opt::eprintf;
use crate::generated::options::R;

#[derive(Default)]
struct State {
    randfiles: Vec<String>,
    save_rand_file: Option<String>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// The list separator of file lists (`LIST_SEPARATOR_CHAR`).
const LIST_SEPARATOR: char = ':';

/// `app_RAND_load_conf`: loads the section's `RANDFILE`, which is then also the file written
/// at exit (unless `-writerand` named one).
pub fn load_conf(randfile: Option<&str>) {
    let Some(randfile) = randfile else {
        return;
    };
    if rand::load_file(randfile) < 0 {
        eprintf!("Can't load {randfile} into RNG\n");
        io::print_errors();
    }
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if s.save_rand_file.is_none() {
            s.save_rand_file = Some(randfile.to_owned());
        }
    });
}

/// `loadfiles`: each file of a `:`-separated list.
fn loadfiles(list: &str) -> bool {
    let mut ret = true;
    let mut rest = list;
    loop {
        let (name, tail) = match rest.split_once(LIST_SEPARATOR) {
            Some((n, t)) => (n, Some(t)),
            None => (rest, None),
        };
        if rand::load_file(name) < 0 {
            eprintf!("Can't load {name} into RNG\n");
            io::print_errors();
            ret = false;
        }
        match tail {
            Some(t) if !t.is_empty() => rest = t,
            _ => break,
        }
    }
    ret
}

/// `app_RAND_load`: the `-rand` files.
pub fn load() -> bool {
    let files = STATE.with(|s| std::mem::take(&mut s.borrow_mut().randfiles));
    let mut ret = true;
    for f in &files {
        if !loadfiles(f) {
            ret = false;
        }
    }
    ret
}

/// `app_RAND_write`: writes the seed file, if one was named.
pub fn write() -> bool {
    let Some(file) = STATE.with(|s| s.borrow_mut().save_rand_file.take()) else {
        return true;
    };
    if rand::write_file(&file) == -1 {
        eprintf!("Cannot write random bytes:\n");
        io::print_errors();
        return false;
    }
    true
}

/// `opt_rand`.
pub fn opt_rand(o: R, arg: &str) -> bool {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        match o {
            R::RAND => s.randfiles.push(arg.to_owned()),
            R::WRITERAND => s.save_rand_file = Some(arg.to_owned()),
        }
    });
    true
}
