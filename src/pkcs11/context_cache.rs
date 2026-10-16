//! Process-lifetime retention of initialized modules, never authenticated sessions.
use crate::error::{Error, Result};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

/// Serialize first initialization and retain loaded contexts, including when
/// all provider handles are dropped. Generic only to test loader behavior without
/// initializing a process-global vendor library in unit tests.
pub(super) struct ModuleCache<T> {
    owner: AtomicU32,
    modules: OnceLock<Mutex<HashMap<PathBuf, Entry<T>>>>,
}

/// A loaded module. `initialized` is false until `C_Initialize` has succeeded
/// (or reported that the module was already initialized). A failed
/// initialization keeps the entry: the vendor library may already have spawned
/// threads before reporting the error, so dropping the only handle would unload
/// their code. Retries reuse the loaded handle and call initialize again.
struct Entry<T> {
    context: T,
    initialized: bool,
}

impl<T: Clone> ModuleCache<T> {
    pub(super) const fn new() -> Self {
        Self {
            owner: AtomicU32::new(0),
            modules: OnceLock::new(),
        }
    }

    /// Check before acquiring any mutex: a fork can inherit a permanently locked
    /// mutex or an initialization in progress. Exec is required in that child.
    pub(super) fn check_process(&self) -> Result<()> {
        let pid = std::process::id();
        let owner = self
            .owner
            .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|owner| owner);
        if owner != 0 && owner != pid {
            return Err(Error::Pkcs11("PKCS#11 module cache inherited across fork; exec before using PKCS#11 in the child".into()));
        }
        Ok(())
    }

    /// Return the initialized context for `path`, loading and initializing it
    /// on first use. `load` must only load the module and resolve its entry
    /// points, never initialize it: a load error stores nothing, so the handle
    /// it held is released. `initialize` runs on the retained handle.
    pub(super) fn get_or_load(
        &self,
        path: &Path,
        load: impl FnOnce(&Path) -> Result<T>,
        initialize: impl FnOnce(&T) -> Result<()>,
    ) -> Result<T> {
        self.check_process()?;
        // Canonicalization shares relative paths and symlinks. Require an actual
        // configured file rather than depending on platform loader search paths.
        let path = path
            .canonicalize()
            .map_err(|e| Error::Pkcs11(format!("cannot resolve PKCS#11 library path: {e}")))?;
        let mut modules = self
            .modules
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| Error::Pkcs11("PKCS#11 module cache lock poisoned".into()))?;
        // Holding the lock through load and initialize prevents concurrent
        // duplicate dlopen and C_Initialize calls.
        let entry = match modules.entry(path) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let context = load(entry.key())?;
                entry.insert(Entry {
                    context,
                    initialized: false,
                })
            }
        };
        if !entry.initialized {
            // On error the loaded handle stays in the map, never unloaded, and
            // the next call retries initialization on the same handle.
            initialize(&entry.context)?;
            entry.initialized = true;
        }
        Ok(entry.context.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_callers_load_once_and_keep_the_context() {
        // The executable supplies a real path without requiring an HSM fixture.
        let path = std::env::current_exe().unwrap();
        let cache = ModuleCache::new();
        let calls = AtomicU32::new(0);
        let barrier = Barrier::new(8);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        cache
                            .get_or_load(
                                &path,
                                |_| {
                                    calls.fetch_add(1, Ordering::SeqCst);
                                    Ok(Arc::new(42))
                                },
                                |_| Ok(()),
                            )
                            .unwrap()
                    })
                })
                .collect();
            let contexts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(contexts.iter().all(|c| Arc::ptr_eq(c, &contexts[0])));
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // All caller handles have gone away, but the cache still owns the value.
        assert_eq!(
            *cache
                .get_or_load(
                    &path,
                    |_| panic!("must remain cached"),
                    |_| panic!("must remain initialized"),
                )
                .unwrap(),
            42
        );
    }

    #[test]
    fn failed_load_leaves_nothing_cached_and_can_be_retried() {
        let path = std::env::current_exe().unwrap();
        let cache = ModuleCache::new();
        assert!(cache
            .get_or_load(
                &path,
                |_| Err::<u32, _>(Error::Pkcs11("fixture failure".into())),
                |_| panic!("must not initialize an unloaded module"),
            )
            .is_err());
        assert_eq!(cache.get_or_load(&path, |_| Ok(7), |_| Ok(())).unwrap(), 7);
    }

    #[test]
    fn failed_initialization_keeps_the_handle_and_retries_on_it() {
        // A vendor module may start threads in C_Initialize even when it then
        // reports an error, so the loaded handle must never be dropped.
        let path = std::env::current_exe().unwrap();
        let cache = ModuleCache::new();
        let loaded = Arc::new(7);
        let weak = Arc::downgrade(&loaded);
        let init_calls = AtomicU32::new(0);
        let err = cache
            .get_or_load(
                &path,
                |_| Ok(loaded),
                |_| {
                    init_calls.fetch_add(1, Ordering::SeqCst);
                    Err(Error::Pkcs11("fixture C_Initialize failure".into()))
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("fixture C_Initialize failure"));
        assert!(
            weak.upgrade().is_some(),
            "handle unloaded after failed init"
        );

        // The retry must not load again: it initializes the retained handle.
        let retried = cache
            .get_or_load(
                &path,
                |_| panic!("must reuse the loaded handle"),
                |context| {
                    init_calls.fetch_add(1, Ordering::SeqCst);
                    assert!(Arc::ptr_eq(context, &weak.upgrade().unwrap()));
                    Ok(())
                },
            )
            .unwrap();
        assert!(Arc::ptr_eq(&retried, &weak.upgrade().unwrap()));
        assert_eq!(init_calls.load(Ordering::SeqCst), 2);

        // Once initialized, neither closure runs again.
        drop(retried);
        assert_eq!(
            *cache
                .get_or_load(
                    &path,
                    |_| panic!("must remain cached"),
                    |_| panic!("must remain initialized"),
                )
                .unwrap(),
            7
        );
    }

    #[test]
    fn different_module_paths_have_independent_contexts() {
        let cache = ModuleCache::new();
        let executable = std::env::current_exe().unwrap();
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert_eq!(
            cache
                .get_or_load(&executable, |_| Ok(1), |_| Ok(()))
                .unwrap(),
            1
        );
        assert_eq!(
            cache.get_or_load(&manifest, |_| Ok(2), |_| Ok(())).unwrap(),
            2
        );
        assert_eq!(
            cache
                .get_or_load(&executable, |_| panic!("must be cached"), |_| Ok(()))
                .unwrap(),
            1
        );
    }

    #[test]
    fn inherited_cache_is_rejected_before_locking() {
        let cache = ModuleCache::<u32>::new();
        cache
            .owner
            .store(std::process::id().wrapping_add(1), Ordering::SeqCst);
        let _guard = cache
            .modules
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap();
        assert!(cache
            .get_or_load(
                Path::new("unused"),
                |_| panic!("must not load"),
                |_| panic!("must not initialize"),
            )
            .unwrap_err()
            .to_string()
            .contains("inherited across fork"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_aliases_share_one_context() {
        let path = std::env::current_exe().unwrap();
        let alias =
            std::env::temp_dir().join(format!("kryptering-cache-alias-{}", std::process::id()));
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        let cache = ModuleCache::new();
        assert_eq!(cache.get_or_load(&path, |_| Ok(9), |_| Ok(())).unwrap(), 9);
        let result = cache.get_or_load(
            &alias,
            |_| panic!("alias must share the context"),
            |_| Ok(()),
        );
        std::fs::remove_file(alias).unwrap();
        assert_eq!(result.unwrap(), 9);
    }
}
