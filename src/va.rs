/// A virtual address in the loaded binary's address space.
///
/// Newtype wrapper around `u64` to prevent accidental mixing of virtual
/// addresses with file offsets, sizes, or raw integer immediates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Va(pub u64);

impl Va {
    pub const ZERO: Va = Va(0);

    /// Raw `u64` value.
    #[inline]
    pub fn raw(self) -> u64 {
        self.0
    }
}

// ── Display / Debug ───────────────────────────────────────────────────────────

impl std::fmt::Debug for Va {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Va(0x{:x})", self.0)
    }
}

impl std::fmt::Display for Va {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl std::fmt::LowerHex for Va {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl std::fmt::UpperHex for Va {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.0, f)
    }
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

impl std::ops::Add<u64> for Va {
    type Output = Va;
    #[inline]
    fn add(self, rhs: u64) -> Va {
        Va(self.0.wrapping_add(rhs))
    }
}

impl std::ops::AddAssign<u64> for Va {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl std::ops::Sub<u64> for Va {
    type Output = Va;
    #[inline]
    fn sub(self, rhs: u64) -> Va {
        Va(self.0.wrapping_sub(rhs))
    }
}

impl std::ops::Sub<Va> for Va {
    type Output = u64;
    #[inline]
    fn sub(self, rhs: Va) -> u64 {
        self.0.wrapping_sub(rhs.0)
    }
}

// ── Conversions ───────────────────────────────────────────────────────────────

impl From<u64> for Va {
    #[inline]
    fn from(v: u64) -> Self {
        Va(v)
    }
}

impl From<Va> for u64 {
    #[inline]
    fn from(v: Va) -> Self {
        v.0
    }
}

// ── VaRange ───────────────────────────────────────────────────────────────────

/// A half-open virtual address range `[start, end)`.
///
/// Named alternative to raw `(Va, Va)` tuples, making the semantics of
/// `from_range` / `to_range` filters self-documenting.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaRange {
    pub start: Va,
    pub end: Va,
}

impl VaRange {
    /// Create a new half-open range `[start, end)`.
    #[inline]
    pub fn new(start: Va, end: Va) -> Self {
        Self { start, end }
    }

    /// Returns `true` if `va` is contained in `[start, end)`.
    #[inline]
    pub fn contains(self, va: Va) -> bool {
        va >= self.start && va < self.end
    }

    /// Returns `true` if the range is empty (`start >= end`).
    #[inline]
    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

impl std::fmt::Debug for VaRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VaRange(0x{:x}..0x{:x})", self.start.0, self.end.0)
    }
}

impl std::fmt::Display for VaRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[0x{:x}, 0x{:x})", self.start.0, self.end.0)
    }
}

// ── Serde ─────────────────────────────────────────────────────────────────────

impl serde::Serialize for Va {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Va {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u64::deserialize(deserializer).map(Va)
    }
}
